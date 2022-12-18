#include <atomic>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <immintrin.h>

#include <fmt/core.h>

using atomic_uint32_t = std::atomic<uint32_t>;
using u8 = uint8_t;

constexpr size_t PAGESIZE = 0x1000;

constexpr size_t DATA_BUF_SIZE = 4 * PAGESIZE;

// offsets in the memfd file
constexpr size_t MEMFD_OFFSET_CTRL = 0x0;
constexpr size_t MEMFD_OFFSET_DC2P = MEMFD_OFFSET_CTRL + 1 * PAGESIZE;
constexpr size_t MEMFD_OFFSET_DP2C = MEMFD_OFFSET_DC2P + DATA_BUF_SIZE;
constexpr size_t MEMFD_OFFSET_SIZE = MEMFD_OFFSET_DP2C + DATA_BUF_SIZE;

#define perror_abort(msg) []{ perror(msg); abort(); }()

void close_all_fds_but(const std::vector<int> &kept_fds)
{
	// TODO (see /proc/self/fd/)
	(void)kept_fds;
}

static void busy_wait(int64_t dt)
{
	for (int64_t i = 0; i < dt; ++i) {
		_mm_pause();
	}
}

static int futex(atomic_uint32_t *uaddr, int futex_op, uint32_t val,
		const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
   return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

// futex condition variable
// (only one waiter and one poster allowed)
struct FuCVar {
	// futex values:
	// * 0: receiving side is waiting with busy wait (or will check value before
	//      futexing) => needs no wake
	// * 1: it's posted
	// * 2: receiving side is waiting with futex syscall
	atomic_uint32_t m_futex;

	explicit FuCVar(bool start_posted = false) : m_futex(start_posted ? 1 : 0)
	{
	}

	void wait()
	{
		// try busy waiting
		for (int i = 0; i < 100; ++i) {
			// posted?
			if (std::atomic_exchange(&m_futex, 0) == 1)
				return; // yes

			busy_wait(40);
		}

		// wait with futex
		while (true) {
			// write 2 to show that we're futexing
			if (std::atomic_exchange(&m_futex, 2) == 1) {
				// futex was posted => change 2 to 0 (or 1 to 1)
				std::atomic_fetch_and(&m_futex, 1);
				return;
			}

			long s = futex(&m_futex, FUTEX_WAIT, 2, nullptr, nullptr, 0);
			if (s == -1 && errno != EAGAIN)
				perror_abort("FuCVar::wait() futex");
		}
	}

	void post()
	{
		uint32_t oldval = std::atomic_exchange(&m_futex, 1);
		if (oldval == 2) {
			long s = futex(&m_futex, FUTEX_WAKE, 1, nullptr, nullptr, 0);
			if (s  == -1)
				perror_abort("FuCVar::post() futex");
		}
	}
};

struct SharedControl {
	FuCVar fucvar_c2p;
	FuCVar fucvar_p2c;
};

static_assert(sizeof(SharedControl) <= 1 * PAGESIZE, "SharedControl too big.");

struct IPCChannel {
	SharedControl *m_ctrl;
	FuCVar *m_fucvar_send;
	u8 *m_shared_data_send = nullptr;
	FuCVar *m_fucvar_recv;
	u8 *m_shared_data_recv = nullptr;

	IPCChannel(const IPCChannel &) = delete;
	IPCChannel(IPCChannel &&) = delete;
	IPCChannel &operator=(const IPCChannel &) = delete;
	IPCChannel &operator=(IPCChannel &&) = delete;

	IPCChannel(int memfd, bool is_parent)
	{
		void *mmapped_ctrl = mmap(nullptr, 1 * PAGESIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED, memfd, MEMFD_OFFSET_CTRL);
		if (mmapped_ctrl == MAP_FAILED)
			perror_abort("mmap");

		// mmaps the same (shared data) region again behind itself
		// (this will later be useful for a ringbuffer)
		auto mmap_data_twice = [&](off_t offset) -> void * {
			std::vector<void *> earlier_tries;
			constexpr int num_tries = 20;
			for (int i = 0; i < num_tries; ++i) {
				void *mmapped_region1 = mmap(nullptr, DATA_BUF_SIZE, PROT_READ | PROT_WRITE,
						MAP_SHARED, memfd, offset);
				if (mmapped_region1 == MAP_FAILED)
					perror_abort("mmap");

				auto try_mmap_fixed = [&](void *addr) {
					void *mmapped_region2 = mmap(addr, DATA_BUF_SIZE, PROT_READ | PROT_WRITE,
							MAP_SHARED | MAP_FIXED_NOREPLACE, memfd, offset);
					if (mmapped_region2 == addr) {
						// it worked
						for (void *region : earlier_tries) {
							if (munmap(region, DATA_BUF_SIZE) == -1)
								perror_abort("munmap");
						}
						return true;
					} else if (mmapped_region2 != MAP_FAILED) {
						fmt::print("mmap with MAP_FIXED_NOREPLACE returned different addr. Not supported?\n");
						abort();
					} else if (errno != EEXIST) {
						perror_abort("mmap with MAP_FIXED_NOREPLACE");
					}
					return false;
				};

				// Note: it is possible (and happens in practice) that mmapped_region1
				// is always mapped before another region (i.e. the last try),
				// so we must try before too
				void *after = (void *)((uintptr_t) mmapped_region1 + DATA_BUF_SIZE);
				void *before = (void *)((uintptr_t) mmapped_region1 - DATA_BUF_SIZE);

				if (try_mmap_fixed(after))
					return mmapped_region1;
				else if (try_mmap_fixed(before))
					return before;

				// try again
				// (unmap later, to avoid mappings always happening at the same place)
				earlier_tries.push_back(mmapped_region1);
			}

			fmt::print("mmap_data_twice keeps failing\n");
			abort();
		};

		void *mmapped_data_c2p = mmap_data_twice(MEMFD_OFFSET_DC2P);
		void *mmapped_data_p2c = mmap_data_twice(MEMFD_OFFSET_DP2C);

		// (no placement new here, it is already initialized)
		m_ctrl = (SharedControl *)mmapped_ctrl;

		if (is_parent) {
			m_fucvar_send = &m_ctrl->fucvar_p2c;
			m_fucvar_recv = &m_ctrl->fucvar_c2p;
			m_shared_data_send = (u8 *)mmapped_data_p2c;
			m_shared_data_recv = (u8 *)mmapped_data_c2p;
		} else {
			m_fucvar_send = &m_ctrl->fucvar_c2p;
			m_fucvar_recv = &m_ctrl->fucvar_p2c;
			m_shared_data_send = (u8 *)mmapped_data_c2p;
			m_shared_data_recv = (u8 *)mmapped_data_p2c;
		}
	}

	~IPCChannel()
	{
		auto munmap_data_twice = [&](void *ptr) {
			void *after = (void *)((uintptr_t) ptr + DATA_BUF_SIZE);
			if (munmap(ptr, DATA_BUF_SIZE) == -1)
				perror_abort("munmap");
			if (munmap(after, DATA_BUF_SIZE) == -1)
				perror_abort("munmap");
		};

		munmap_data_twice(m_shared_data_send);
		munmap_data_twice(m_shared_data_recv);

		if (munmap(m_ctrl, 1 * PAGESIZE) == -1)
			perror_abort("munmap");
	}

	std::string sendSync(const std::string &msg)
	{
		sendRaw(msg);
		return recvRaw();
	}

	void sendRaw(const std::string &msg)
	{
		size_t msg_size = msg.size();
		if (msg_size > DATA_BUF_SIZE - sizeof(msg_size)) {
			fmt::print("msg too long (TODO)\n");
			abort();
		}

		((size_t *)m_shared_data_send)[0] = msg_size;
		u8 *buf_send_after_size = (u8 *)&((size_t *)m_shared_data_send)[1];
		std::memcpy(buf_send_after_size, msg.data(), msg_size);

		m_fucvar_send->post();
	}

	std::string recvRaw()
	{
		m_fucvar_recv->wait();

		size_t answer_size = ((size_t *)m_shared_data_recv)[0];
		if (answer_size > DATA_BUF_SIZE - sizeof(answer_size)) {
			// malicious size
			fmt::print("answer size too long\n");
			abort();
		}
		u8 *buf_recv_after_size = (u8 *)&((size_t *)m_shared_data_recv)[1];

		return std::string((char *)buf_recv_after_size, answer_size);
	}
};

struct SandboxChild {
	int m_memfd = -1;
	pid_t m_child_pid = -1;
	std::unique_ptr<IPCChannel> m_channel;

	SandboxChild(const SandboxChild &) = delete;
	SandboxChild(SandboxChild &&) = delete;
	SandboxChild &operator=(const SandboxChild &) = delete;
	SandboxChild &operator=(SandboxChild &&) = delete;

	SandboxChild()
	{
		m_memfd = memfd_create("ipc_channel", 0);
		if (m_memfd == -1)
			perror_abort("memfd_create");

		if (ftruncate(m_memfd, MEMFD_OFFSET_SIZE) == -1)
			perror_abort("ftruncate");

		// initialize SharedControl
		{
			void *mmapped_ctrl = mmap(nullptr, 1 * PAGESIZE, PROT_READ | PROT_WRITE,
					MAP_SHARED, m_memfd, MEMFD_OFFSET_CTRL);
			if (mmapped_ctrl == MAP_FAILED)
				perror_abort("mmap");

			new(mmapped_ctrl) SharedControl();

			if (munmap(mmapped_ctrl, 1 * PAGESIZE) == -1)
				perror_abort("munmap");
		}

		pid_t pid = fork();
		if (pid == -1) {
		   perror_abort("fork");
		} else if (pid == 0) {
			// child
			std::string arg0 = "/proc/self/exe";
			std::string arg1 = "--child";
			std::string arg2 = std::to_string(m_memfd);
			char *const argv[] = {arg0.data(), arg1.data(), arg2.data(), nullptr};
			char *const envp[] = {nullptr};
			if (execve("/proc/self/exe", argv, envp) == -1)
				perror_abort("execve");
		} else {
			// parent
			m_child_pid = pid;
			m_channel = std::make_unique<IPCChannel>(m_memfd, true);
			std::string answer0 = m_channel->recvRaw();
			if (answer0 != "\x01") {
				fmt::print("[p] first answer must be callback end\n");
				abort();
			}
		}
	}

	~SandboxChild()
	{
		m_channel->sendRaw("\x02"); // please kill yourself
		m_channel.reset();
		waitpid(m_child_pid, nullptr, 0);

		// deinitialize SharedControl
		{
			void *mmapped_ctrl = mmap(nullptr, 1 * PAGESIZE, PROT_READ | PROT_WRITE,
					MAP_SHARED, m_memfd, MEMFD_OFFSET_CTRL);
			if (mmapped_ctrl == MAP_FAILED)
				perror_abort("mmap");

			((SharedControl *)mmapped_ctrl)->~SharedControl();

			if (munmap(mmapped_ctrl, 1 * PAGESIZE) == -1)
				perror_abort("munmap");
		}

		close(m_memfd);
	}
};

constexpr bool do_benchmark = true;

void child_main(int memfd)
{
	auto channel = std::make_unique<IPCChannel>(memfd, false);

	close(memfd);
	close_all_fds_but({});
	// TODO: sandbox

	std::string cb_data;

	bool benchmarking = do_benchmark;

	while (true) {
		cb_data = channel->sendSync("\x01"); // callback end

		if (benchmarking) {
			//~ fmt::print("[c] got: {:x}\n", (int)cb_data[0]);
			if (cb_data.size() != 5) {
				fmt::print("size != 5 (it is {})\n", cb_data.size());
				abort();
			}
			//~ fmt::print("[c] got: {:x}\n", ((int *)&cb_data[1])[0]);
			if (((int *)&cb_data[1])[0] == 0)
				benchmarking = false;
			continue;
		}

		fmt::print("[c] got: {:x}\n", (int)cb_data[0]);

		if (cb_data == "\x02") { // I should kill myself
			break;
		}
	}

	fmt::print("[c] ending...\n");
}

void parent_main()
{
	using namespace std::literals;

	fmt::print("[p] starting...\n");

	SandboxChild ipc_thing;

	if (do_benchmark) {
		auto timediff_seconds = [](struct timespec t1, struct timespec t0) -> double {
				return t1.tv_sec - t0.tv_sec + 1.0e-9 * (t1.tv_nsec - t0.tv_nsec);
			};

		static constexpr int num_calls = 1000000;
		struct timespec t0;
		struct timespec t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);

		for (int val = num_calls-1; val >= 0; --val) {
			std::string msg("\0\0\0\0\0"sv);
			((int *)&msg[1])[0] = val;
			std::string answer = ipc_thing.m_channel->sendSync(msg);
			(void)answer;
		}

		clock_gettime(CLOCK_MONOTONIC, &t1);
		double dt = timediff_seconds(t1, t0);
		fmt::print("[p] dt = {} s; per call: {} ns\n", dt, dt / num_calls * 1e9);

	} else {
		std::string answer = ipc_thing.m_channel->sendSync("\x42");
		fmt::print("[p] got: {:x}\n", (int)answer[0]);
	}

	fmt::print("[p] ending...\n");
}

int main(int argc, char *argv[])
{
	using namespace std::literals;

	setbuf(stdout, nullptr);

	if (argc == 3 && argv[1] == "--child"sv) {
		child_main(atoi(argv[2]));
		fmt::print("[c] ended.\n");
		return 0;
	}

	parent_main();
	fmt::print("[p] ended.\n");

	return 0;
}
