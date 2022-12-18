
mt_futex_ipc: mt_futex_ipc.cpp
	g++ -O2 -march=native -Wall -Wextra -std=c++17 -g -o "mt_futex_ipc" "mt_futex_ipc.cpp" -lfmt
