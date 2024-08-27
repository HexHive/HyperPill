#include <sqlite3.h>
#include <stdio.h>
#include <map>
#include "fuzz.h"


sqlite3 *db;
void open_db(const char* path) {
    char *err_msg = 0;

    int rc = sqlite3_open(path, &db);

    if (rc != SQLITE_OK) {

        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);

        return;
    }

    const char *sql = "CREATE TABLE MMIO(Address INT, Length INT); "
                "CREATE TABLE PIO(Address INT, Length INT);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
}

void insert_mmio(uint64_t addr, uint64_t len){
    sqlite3_stmt *res;
    const char *sql = "INSERT INTO MMIO(Address, Length) VALUES (?, ?);";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_int64(res, 1, addr);
    sqlite3_bind_int64(res, 2, len);
    int step = sqlite3_step(res);
    sqlite3_finalize(res);
}

void insert_pio(uint16_t addr, uint16_t len){
    sqlite3_stmt *res;
    const char *sql = "INSERT INTO PIO(Address, Length) VALUES (?, ?);";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    sqlite3_bind_int(res, 1, addr);
    sqlite3_bind_int(res, 2, len);
    int step = sqlite3_step(res);
    sqlite3_finalize(res);
}

void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<bx_address, uint32_t> &mmio_regions) {
    sqlite3_stmt *res;
    const char *sql = "SELECT Address, Length from PIO";
    int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    int step;
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        if(sqlite3_column_int64(res, 1)) {
            pio_regions[sqlite3_column_int64(res, 0)] = sqlite3_column_int64(res, 1);
            printf("Loaded PIO Region: %lx +%lx\n", 
                    sqlite3_column_int64(res, 0),
                    sqlite3_column_int64(res, 1));
        }
    }
    sql = "SELECT Address, Length from MMIO";
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    while((step = sqlite3_step(res)) == SQLITE_ROW) {
        if(sqlite3_column_int64(res, 1)){
            printf("Loaded MMIO Region: %lx +%lx\n", 
                    sqlite3_column_int64(res, 0),
                    sqlite3_column_int64(res, 1));
            mmio_regions[sqlite3_column_int64(res, 0)] = sqlite3_column_int64(res, 1);
        }
    }
}
