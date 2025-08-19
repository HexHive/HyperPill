#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>
#include <sys/stat.h>
#include <atomic>

static std::map<std::string, int> generation_counters;
static std::map<std::string, int> mutator_counters;
static std::map<std::string, int> get_counters;
static std::map<std::string, int> op_counters;
static std::mutex counters_mutex;
static const std::chrono::seconds write_interval(60); // Adjust the interval as needed
static std::thread background_thread;
static std::chrono::time_point<std::chrono::steady_clock> start_time;
static std::atomic<bool> file_cleared(false);

void clearFile(const std::string& filename) {
    std::ofstream outFile(filename, std::ios_base::trunc);
    if (outFile.is_open()) {
        outFile.close();
        file_cleared = true;
    } else {
        std::cerr << "Unable to clear file: " << filename << std::endl;
    }
}

void writeCountersToFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(counters_mutex);

	if (!file_cleared) {
        clearFile(filename);
    }

    std::ofstream outFile(filename, std::ios_base::app); // Open in append mode
    if (outFile.is_open()) {
        // Calculate the running time
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

        outFile << "Running Time: " << duration << " seconds" << std::endl;

		outFile << std::endl << "Execution:" << std::endl;
        for (const auto& counter : get_counters) {
            outFile << counter.first << ": " << counter.second << std::endl;
        }

		outFile << std::endl << "Generation:" << std::endl;
        for (const auto& counter : generation_counters) {
            outFile << counter.first << ": " << counter.second << std::endl;
        }

		outFile << std::endl << "Mutation:" << std::endl;
		for (const auto& counter : mutator_counters) {
            outFile << counter.first << ": " << counter.second << std::endl;
        }

		outFile << std::endl << "OPs:" << std::endl;
		for (const auto& counter : op_counters) {
            outFile << counter.first << ": " << counter.second << std::endl;
        }

        outFile << std::endl;
        outFile.close();
    } else {
        std::cerr << "Unable to open file for writing generation_counters." << std::endl;
    }
}

void updateGetCounters(const std::string& messageType) {
    std::lock_guard<std::mutex> lock(counters_mutex);
    get_counters[messageType]++;
}

void updateCounters(const std::string& messageType) {
    std::lock_guard<std::mutex> lock(counters_mutex);
    generation_counters[messageType]++;
}

void updateOPCounters(const std::string& messageType) {
    std::lock_guard<std::mutex> lock(counters_mutex);
    op_counters[messageType]++;
}

void updateMutatorCounters(const std::string& mutatorName) {
    std::lock_guard<std::mutex> lock(counters_mutex);
    mutator_counters[mutatorName]++;
}

void backgroundWriter(const std::string& file_path) {
    while (true) {
        writeCountersToFile(file_path);
        std::this_thread::sleep_for(std::chrono::seconds(write_interval));
    }
}

void start_background_writer(const std::string& file_path) {
    std::string json_file_path = std::string(file_path);
    size_t bin_pos = json_file_path.rfind(".json");
    if (bin_pos != std::string::npos) {
		json_file_path.replace(bin_pos, 5, ".stat");
    }

    if (!background_thread.joinable()) {
		start_time = std::chrono::steady_clock::now(); // Set the start time
        background_thread = std::thread(backgroundWriter, json_file_path);
    }
}
