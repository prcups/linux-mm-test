#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

#define MIB (1024ULL * 1024ULL)
#define HOLD_CHUNK_MIB 16UL

struct latency_sample {
	uint64_t latency_ns;
};

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int cmp_latency(const void *a, const void *b)
{
	uint64_t la = ((const struct latency_sample *)a)->latency_ns;
	uint64_t lb = ((const struct latency_sample *)b)->latency_ns;

	return (la > lb) - (la < lb);
}

static size_t percentile_index(size_t count, unsigned int permille)
{
	return (count - 1) * permille / 1000;
}

static int fd_from_env(const char *name)
{
	const char *value = getenv(name);
	char *end;
	long fd;

	if (!value || !*value)
		return -1;

	errno = 0;
	fd = strtol(value, &end, 10);
	if (errno || *end || fd < 0 || fd > INT32_MAX) {
		fprintf(stderr, "Invalid %s value: %s\n", name, value);
		return -2;
	}
	return (int)fd;
}

static int notify_ready(const char *fd_name)
{
	int ready_fd = fd_from_env(fd_name);
	char token = 1;
	ssize_t ret;

	if (ready_fd == -2)
		return -1;
	if (ready_fd < 0)
		return 0;

	do {
		ret = write(ready_fd, &token, sizeof(token));
	} while (ret < 0 && errno == EINTR && running);
	close(ready_fd);
	if (ret != sizeof(token)) {
		fprintf(stderr, "Failed to notify the parent process\n");
		return -1;
	}
	return 0;
}

static int wait_for_start(void)
{
	int ready_fd = fd_from_env("ALLOC_READY_FD");
	int start_fd = fd_from_env("ALLOC_START_FD");
	char token;
	ssize_t ret;

	if (ready_fd == -2 || start_fd == -2)
		return -1;
	if ((ready_fd < 0) != (start_fd < 0)) {
		fprintf(stderr, "Both ALLOC_READY_FD and ALLOC_START_FD are required\n");
		return -1;
	}
	if (ready_fd < 0)
		return 0;

	if (notify_ready("ALLOC_READY_FD"))
		return -1;

	do {
		ret = read(start_fd, &token, sizeof(token));
	} while (ret < 0 && errno == EINTR && running);
	close(start_fd);
	if (ret != sizeof(token)) {
		fprintf(stderr, "Failed to receive the allocation start token\n");
		return -1;
	}
	return 0;
}

static void touch_all_pages(void *ptr, size_t size, unsigned char value)
{
	volatile unsigned char *bytes = ptr;
	size_t offset;

	for (offset = 0; offset < size; offset += PAGE_SIZE)
		bytes[offset] = value;
	if (size)
		bytes[size - 1] = value;
	asm volatile("" ::: "memory");
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [-H] [-o order] [-s target_mib] [-r | -p priority]\n"
		"  -H             hold target_mib resident until terminated\n"
		"  -o order       allocation block size: 4 KiB << order (default 0)\n"
		"  -s target_mib  memory to hold or total bytes processed (default 64)\n"
		"  -r             use SCHED_FIFO priority 50\n"
		"  -p priority    use SCHED_FIFO with the specified priority\n",
		program);
}

static int set_scheduler(int policy, int priority)
{
	struct sched_param param = { .sched_priority = priority };

	if (!sched_setscheduler(0, policy, &param))
		return 0;
	perror(policy == SCHED_FIFO ?
	       "sched_setscheduler SCHED_FIFO" : "sched_setscheduler SCHED_OTHER");
	return -1;
}

static int hold_memory(unsigned long target_mib, int setup_rt_prio)
{
	const size_t chunk_size = HOLD_CHUNK_MIB * MIB;
	uint64_t target_bytes = (uint64_t)target_mib * MIB;
	size_t chunk_count = (target_mib + HOLD_CHUNK_MIB - 1) / HOLD_CHUNK_MIB;
	void **chunks;
	size_t allocated = 0;

	chunks = calloc(chunk_count, sizeof(*chunks));
	if (!chunks) {
		perror("allocate pressure metadata");
		return 1;
	}
	touch_all_pages(chunks, chunk_count * sizeof(*chunks), 0);
	if (setup_rt_prio >= 0 && set_scheduler(SCHED_FIFO, setup_rt_prio)) {
		fprintf(stderr, "Run as root or with CAP_SYS_NICE.\n");
		free(chunks);
		return 1;
	}

	while (allocated < chunk_count && running) {
		uint64_t remaining = target_bytes - (uint64_t)allocated * chunk_size;
		size_t size = remaining < chunk_size ? (size_t)remaining : chunk_size;

		chunks[allocated] = malloc(size);
		if (!chunks[allocated]) {
			fprintf(stderr, "pressure malloc failed at chunk %zu\n", allocated);
			break;
		}
		touch_all_pages(chunks[allocated], size, (unsigned char)allocated);
		allocated++;
	}

	if (allocated != chunk_count ||
	    (setup_rt_prio >= 0 && set_scheduler(SCHED_OTHER, 0)) ||
	    notify_ready("ALLOC_PRESSURE_READY_FD")) {
		for (size_t i = 0; i < allocated; i++)
			free(chunks[i]);
		free(chunks);
		return 1;
	}

	while (running)
		pause();

	for (size_t i = 0; i < allocated; i++)
		free(chunks[i]);
	free(chunks);
	printf("held_mib:      %lu\n", target_mib);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int alloc_order = 0;
	unsigned long target_mib = 64;
	int rt_prio = -1;
	int hold_mode = 0;
	uint64_t target_bytes;
	uint64_t iteration_count;
	size_t alloc_size;
	size_t iterations;
	struct latency_sample *samples;
	size_t recorded = 0;
	int allocation_failed = 0;
	int opt;

	while ((opt = getopt(argc, argv, "Ho:p:rs:h")) != -1) {
		switch (opt) {
		case 'H':
			hold_mode = 1;
			break;
		case 'o':
			alloc_order = (unsigned int)strtoul(optarg, NULL, 10);
			break;
		case 'p':
			rt_prio = atoi(optarg);
			break;
		case 'r':
			rt_prio = 50;
			break;
		case 's':
			target_mib = strtoul(optarg, NULL, 10);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!target_mib ||
	    (uint64_t)target_mib > UINT64_MAX / MIB ||
	    target_mib > SIZE_MAX / MIB) {
		fprintf(stderr, "Invalid memory target\n");
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	if (hold_mode) {
		return hold_memory(target_mib, rt_prio);
	}

	if (alloc_order >= sizeof(size_t) * 8 ||
	    PAGE_SIZE > (SIZE_MAX >> alloc_order) ||
	    (uint64_t)target_mib > UINT64_MAX / MIB) {
		fprintf(stderr, "Invalid allocation size or target\n");
		return 1;
	}

	alloc_size = PAGE_SIZE << alloc_order;
	target_bytes = (uint64_t)target_mib * MIB;
	iteration_count = target_bytes / alloc_size;
	if (target_bytes % alloc_size)
		iteration_count++;
	if (!iteration_count || iteration_count > SIZE_MAX) {
		fprintf(stderr, "Target is too large for this architecture\n");
		return 1;
	}

	iterations = (size_t)iteration_count;
	if (iterations > SIZE_MAX / sizeof(*samples)) {
		fprintf(stderr, "Target is too large for this architecture\n");
		return 1;
	}

	samples = calloc(iterations, sizeof(*samples));
	if (!samples) {
		perror("allocate test metadata");
		return 1;
	}

	/* Fault metadata in before entering the measured allocation loop. */
	touch_all_pages(samples, iterations * sizeof(*samples), 0);

	/* Prime the userspace allocator before switching to realtime policy. */
	void *warmup = malloc(PAGE_SIZE);
	if (!warmup) {
		perror("warmup malloc");
		free(samples);
		return 1;
	}
	touch_all_pages(warmup, PAGE_SIZE, 0x5a);
	free(warmup);

	if (rt_prio >= 0) {
		if (set_scheduler(SCHED_FIFO, rt_prio)) {
			fprintf(stderr, "Run as root or with CAP_SYS_NICE.\n");
			free(samples);
			return 1;
		}
	}
	if (wait_for_start()) {
		free(samples);
		return 1;
	}

	for (size_t i = 0; i < iterations && running; i++) {
		uint64_t start;
		uint64_t end;
		void *ptr;

		start = now_ns();
		asm volatile("" ::: "memory");

		ptr = malloc(alloc_size);
		if (!ptr) {
			fprintf(stderr, "malloc failed at allocation %zu\n", i);
			allocation_failed = 1;
			break;
		}

		touch_all_pages(ptr, alloc_size, (unsigned char)i);
		end = now_ns();

		samples[recorded].latency_ns = end - start;
		recorded++;
		free(ptr);
	}

	printf("rt_prio:       %d\n", rt_prio);
	printf("target_mib:    %lu\n", target_mib);
	printf("processed_mib: %.2f\n", (double)recorded * alloc_size / MIB);
	printf("allocations:   %zu\n", recorded);
	printf("block_order:   %u (%zu bytes)\n", alloc_order, alloc_size);

	if (recorded) {
		qsort(samples, recorded, sizeof(*samples), cmp_latency);
		printf("P50:  %8llu ns\n",
		       (unsigned long long)samples[percentile_index(recorded, 500)].latency_ns);
		printf("P90:  %8llu ns\n",
		       (unsigned long long)samples[percentile_index(recorded, 900)].latency_ns);
		printf("P99:  %8llu ns\n",
		       (unsigned long long)samples[percentile_index(recorded, 990)].latency_ns);
		printf("P99.9:%8llu ns\n",
		       (unsigned long long)samples[percentile_index(recorded, 999)].latency_ns);
		printf("MAX:  %8llu ns\n",
		       (unsigned long long)samples[recorded - 1].latency_ns);
	}

	free(samples);
	return allocation_failed || !running ? 1 : 0;
}
