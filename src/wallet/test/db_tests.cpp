// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <fs.h>
#include <test/util/setup_common.h>
#include <util/translation.h>
#ifdef USE_BDB
#include <wallet/bdb.h>
#endif
#ifdef USE_SQLITE
#include <wallet/sqlite.h>
#endif
#include <wallet/walletutil.h> // for WALLET_FLAG_DESCRIPTORS

#include <fstream>
#include <memory>
#include <string>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(db_tests, BasicTestingSetup)

static std::shared_ptr<BerkeleyEnvironment> GetWalletEnv(const fs::path& path, fs::path& database_filename)
{
    fs::path data_file = BDBDataFile(path);
    database_filename = data_file.filename();
    return GetBerkeleyEnv(data_file.parent_path(), false);
}

BOOST_AUTO_TEST_CASE(getwalletenv_file)
{
    fs::path test_name = "test_name.dat";
    const fs::path datadir = m_args.GetDataDirNet();
    fs::path file_path = datadir / test_name;
    std::ofstream f{file_path};
    f.close();

    fs::path filename;
    std::shared_ptr<BerkeleyEnvironment> env = GetWalletEnv(file_path, filename);
    BOOST_CHECK_EQUAL(filename, test_name);
    BOOST_CHECK_EQUAL(env->Directory(), datadir);
}

BOOST_AUTO_TEST_CASE(getwalletenv_directory)
{
    fs::path expected_name = "wallet.dat";
    const fs::path datadir = m_args.GetDataDirNet();

    fs::path filename;
    std::shared_ptr<BerkeleyEnvironment> env = GetWalletEnv(datadir, filename);
    BOOST_CHECK_EQUAL(filename, expected_name);
    BOOST_CHECK_EQUAL(env->Directory(), datadir);
}

BOOST_AUTO_TEST_CASE(getwalletenv_g_dbenvs_multiple)
{
    fs::path datadir = m_args.GetDataDirNet() / "1";
    fs::path datadir_2 = m_args.GetDataDirNet() / "2";
    fs::path filename;

    std::shared_ptr<BerkeleyEnvironment> env_1 = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_2 = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_3 = GetWalletEnv(datadir_2, filename);

    BOOST_CHECK(env_1 == env_2);
    BOOST_CHECK(env_2 != env_3);
}

BOOST_AUTO_TEST_CASE(getwalletenv_g_dbenvs_free_instance)
{
    fs::path datadir = gArgs.GetDataDirNet() / "1";
    fs::path datadir_2 = gArgs.GetDataDirNet() / "2";
    fs::path filename;

    std::shared_ptr <BerkeleyEnvironment> env_1_a = GetWalletEnv(datadir, filename);
    std::shared_ptr <BerkeleyEnvironment> env_2_a = GetWalletEnv(datadir_2, filename);
    env_1_a.reset();

    std::shared_ptr<BerkeleyEnvironment> env_1_b = GetWalletEnv(datadir, filename);
    std::shared_ptr<BerkeleyEnvironment> env_2_b = GetWalletEnv(datadir_2, filename);

    BOOST_CHECK(env_1_a != env_1_b);
    BOOST_CHECK(env_2_a == env_2_b);
}

BOOST_AUTO_TEST_CASE(db_cursor_prefix_range_test)
{
    std::vector<std::unique_ptr<WalletDatabase>> dbs;

    // Create dbs
    DatabaseOptions options;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
#ifdef USE_BDB
    dbs.emplace_back(MakeBerkeleyDatabase(m_path_root / "bdb", options, status, error));
#endif
#ifdef USE_SQLITE
    dbs.emplace_back(MakeSQLiteDatabase(m_path_root / "sqlite", options, status, error));
#endif

    // Test each supported db
    for (const auto& database : dbs) {
        BOOST_ASSERT(database);

        std::string FIRST_KEY = "FIRST"; // stores std::vector<int>
        std::string SECOND_KEY = "SECOND"; // stores int

        // Write elements to it
        std::unique_ptr<DatabaseBatch> handler = database->MakeBatch();
        for (unsigned int i = 0; i < 10; i++) {
            BOOST_CHECK(handler->Write(std::make_pair(FIRST_KEY, i), std::vector<unsigned int>({i})));
            BOOST_CHECK(handler->Write(std::make_pair(SECOND_KEY, i), i));
        }

        // Now read all the first key items and verify that each element gets parsed correctly
        CDataStream prefix(0, 0);
        prefix << FIRST_KEY;
        std::unique_ptr<DatabaseCursor> cursor = handler->GetNewPrefixCursor(prefix);
        CDataStream key(0, 0);
        CDataStream value(0, 0);
        bool complete;
        for (int i = 0; i < 10; i++) {
            BOOST_CHECK(cursor->Next(key, value, complete));
            BOOST_ASSERT(!complete);

            std::string key_back;
            key >> key_back;
            BOOST_CHECK_EQUAL(key_back, FIRST_KEY);

            std::vector<unsigned int> value_back;
            value >> value_back;
            BOOST_CHECK_EQUAL(value_back.at(0), i);
        }

        // Let's now read it once more, it should return complete=true and fail
        BOOST_CHECK(!cursor->Next(key, value, complete));
        BOOST_ASSERT(complete);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
