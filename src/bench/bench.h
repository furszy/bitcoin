// Copyright (c) 2015-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BENCH_BENCH_H
#define BITCOIN_BENCH_BENCH_H

#include <fs.h>
#include <util/macros.h>

#include <chrono>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <bench/nanobench.h>

/*
 * Usage:

static void NameOfYourBenchmarkFunction(benchmark::Bench& bench)
{
    ...do any setup needed...

    bench.run([&] {
         ...do stuff you want to time; refer to src/bench/nanobench.h
            for more information and the options that can be passed here...
    });

    ...do any cleanup needed...
}

BENCHMARK(NameOfYourBenchmarkFunction);

 */

namespace benchmark {

using ankerl::nanobench::Bench;

typedef std::function<void(Bench&)> BenchFunction;

enum BenchPriorityLevel
{
    HIGH,
    MEDIUM,
    LOW
};

BenchPriorityLevel ToPriorityLevel(const std::string& str);
std::string PriorityToString(BenchPriorityLevel level);

struct Args {
    bool is_list_only;
    bool sanity_check;
    std::chrono::milliseconds min_time;
    std::vector<double> asymptote;
    fs::path output_csv;
    fs::path output_json;
    std::string regex_filter;
    BenchPriorityLevel priority_level{HIGH};
};

class BenchRunner
{
    typedef std::map<BenchPriorityLevel, std::map<std::string, BenchFunction>> BenchmarkMap;
    static BenchmarkMap& benchmarks();

public:
    BenchRunner(std::string name, BenchFunction func, BenchPriorityLevel level);

    static void RunAll(const Args& args);
};
} // namespace benchmark

// BENCHMARK(foo) expands to:  benchmark::BenchRunner bench_11foo("foo", foo, priority_level);
#define BENCHMARK(n, priority_level) \
    benchmark::BenchRunner PASTE2(bench_, PASTE2(__LINE__, n))(STRINGIZE(n), n, priority_level);

#endif // BITCOIN_BENCH_BENCH_H
