// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

// Test LegacyScriptPubKeyMan::CanProvide behavior, making sure it returns true
// for recognized scripts even when keys may not be available for signing.
BOOST_AUTO_TEST_CASE(CanProvide)
{
    // Set up wallet and keyman variables.
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Make a 1 of 2 multisig script
    std::vector<CKey> keys(2);
    std::vector<CPubKey> pubkeys;
    for (CKey& key : keys) {
        key.MakeNewKey(true);
        pubkeys.emplace_back(key.GetPubKey());
    }
    CScript multisig_script = GetScriptForMultisig(1, pubkeys);
    CScript p2sh_script = GetScriptForDestination(ScriptHash(multisig_script));
    SignatureData data;

    // Verify the p2sh(multisig) script is not recognized until the multisig
    // script is added to the keystore to make it solvable
    BOOST_CHECK(!keyman.CanProvide(p2sh_script, data));
    keyman.AddCScript(multisig_script);
    BOOST_CHECK(keyman.CanProvide(p2sh_script, data));
}

class TestDescriptorSPKM : public DescriptorScriptPubKeyMan {
public:
    explicit TestDescriptorSPKM(WalletStorage& storage) :  DescriptorScriptPubKeyMan(storage) {}
    std::unique_ptr<FlatSigningProvider> GetSigningProviderByIndex(int32_t index, bool include_private = false) const {
        return GetSigningProvider(index, include_private);
    }
    std::map<int32_t, FlatSigningProvider> GetSigningProvidersCache() { return DescriptorScriptPubKeyMan::GetSigningProvidersCache(); }
};

// Sanity check for any future modification, the sk must not be cached inside the signing providers cache
BOOST_FIXTURE_TEST_CASE(wallet_descriptor_signing_providers_cache_test, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());

    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    OutputType output_type = OutputType::BECH32;

    // Create descriptor
    CKey seed_key;
    seed_key.MakeNewKey(true);
    CExtKey master_key;
    master_key.SetSeed(seed_key);
    auto spk_manager = std::unique_ptr<TestDescriptorSPKM>(new TestDescriptorSPKM(wallet));
    spk_manager->SetupDescriptorGeneration(master_key, output_type, false);
    auto descriptor = spk_manager->GetWalletDescriptor();

    int INTERATIONS = 20;
    std::vector<CKeyID> ids;
    for (int index = 0; index < INTERATIONS ; index++) {
        // Create destination
        CTxDestination dest;
        bilingual_str error;
        BOOST_ASSERT(spk_manager->GetNewDestination(*descriptor.descriptor->GetOutputType(), dest, error));
        CKeyID dest_key_id = ToKeyID(std::get<WitnessV0KeyHash>(dest));
        CScript dest_script = GetScriptForDestination(dest);
        ids.emplace_back(dest_key_id);

        // Check signing provider without sk
        auto signing_provider_without_sk = spk_manager->GetSigningProviderByIndex(index, false);
        BOOST_CHECK(signing_provider_without_sk);
        CPubKey ret_pubkey_without_sk;
        BOOST_CHECK(signing_provider_without_sk->GetPubKey(dest_key_id, ret_pubkey_without_sk));
        BOOST_CHECK(!signing_provider_without_sk->HaveKey(dest_key_id));

        // Check signing provider with sk
        auto signing_provider_with_sk = spk_manager->GetSigningProviderByIndex(index, true);
        BOOST_CHECK(signing_provider_with_sk);
        CPubKey ret_pubkey_with_sk;
        BOOST_CHECK(signing_provider_with_sk->GetPubKey(dest_key_id, ret_pubkey_with_sk));
        CKey ret_key_with_sk;
        BOOST_CHECK(signing_provider_with_sk->GetKey(dest_key_id, ret_key_with_sk));

        // Compare both now
        BOOST_CHECK(ret_pubkey_without_sk == ret_pubkey_with_sk);

        // Get the signing provider without the sk again and verify that the sk is not retrieved.
        auto signing_provider_without_sk_2 = spk_manager->GetSigningProviderByIndex(index, false);
        BOOST_CHECK(signing_provider_without_sk_2);
        CPubKey ret_pubkey_without_sk_2;
        BOOST_CHECK(signing_provider_without_sk_2->GetPubKey(dest_key_id, ret_pubkey_without_sk_2));
        BOOST_CHECK(!signing_provider_without_sk_2->HaveKey(dest_key_id));
        BOOST_CHECK(ret_pubkey_without_sk == ret_pubkey_without_sk_2);
    }

    // Check that no sk was stored in the cache
    auto map = spk_manager->GetSigningProvidersCache();
    for (int index = 0; index < INTERATIONS ; index++) {
        BOOST_CHECK(!map.at(index).HaveKey(ids[index]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
