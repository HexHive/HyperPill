#ifndef STATISTICS_H
#define STATISTICS_H

#include <iostream>

void writeCountersToFile(const std::string& filename);
void updateCounters(const std::string& messageType);
void updateGetCounters(const std::string& messageType);
void updateOPCounters(const std::string& messageType);
void updateMutatorCounters(const std::string& mutatorName);
void backgroundWriter(const std::string& file_path);
void start_background_writer(const std::string& file_path);

#endif

