#include <benchmark/benchmark.h>

#include <rte_eal.h>

int main(int argc, char **argv) {
    fprintf(stderr, "EAL init\n");
    int eal_argc = 5;
    char const **eal_argv = new char const *[eal_argc];
    eal_argv[0] = "test";
    eal_argv[1] = "--main-lcore";
    eal_argv[2] = "31";
    eal_argv[3] = "-l";
    eal_argv[4] = "31";
    int ret = rte_eal_init(eal_argc, (char **)eal_argv);
    delete[] eal_argv;
    eal_argv = NULL;
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();

    rte_eal_cleanup();
    fprintf(stderr, "EAL cleanup\n");
    return 0;
}
