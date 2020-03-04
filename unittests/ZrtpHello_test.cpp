//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 28.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <zrtp/libzrtpcpp/ZrtpConfigure.h>
#include <zrtp/libzrtpcpp/ZRtp.h>
#include "../logging/ZrtpLogging.h"
#include "ZrtpTestCommon.h"

using namespace std;

using testing::_;
using testing::Ge;
using testing::Return;
using testing::SaveArg;
using testing::DoAll;

string aliceId;
string BobId;
uint8_t aliceZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t bobZid[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

class ZrtpHelloTestFixture: public ::testing::Test {
public:
    ZrtpHelloTestFixture() = default;

    ZrtpHelloTestFixture(const ZrtpHelloTestFixture& other) = delete;
    ZrtpHelloTestFixture(const ZrtpHelloTestFixture&& other) = delete;
    ZrtpHelloTestFixture& operator= (const ZrtpHelloTestFixture& other) = delete;
    ZrtpHelloTestFixture& operator= (const ZrtpHelloTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
        aliceId = "test zid 1";
        BobId = "test zid 2";
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpHelloTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        aliceId.clear();
        BobId.clear();
    }
};

// ZRtp::ZRtp(uint8_t *myZid, ZrtpCallback& cb, const string& id, shared_ptr<ZrtpConfigure>& config, bool mitm, bool sasSignSupport)

TEST_F(ZrtpHelloTestFixture, HelloPacketConfigMandatory) {
    /* Configure with mandatory algorithms only:
    HashAlgorithm:   s256
    CipherAlgorithm: aes1
    PubKeyAlgorithm: dh3k, mult
    SasType: b32
    AuthLength: hs32, hs80
    */
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    ZrtpPacketHello hpExpected;
    hpExpected.configureHello(*configure);
    ASSERT_EQ(1, hpExpected.getNumHashes());
    ASSERT_EQ(1, hpExpected.getNumCiphers());
    ASSERT_EQ(2, hpExpected.getNumPubKeys());
    ASSERT_EQ(1, hpExpected.getNumSas());
    ASSERT_EQ(2, hpExpected.getNumAuth());

    ASSERT_EQ(string("S256"), string((char *)hpExpected.getHashType(0), 4));
    ASSERT_EQ(string("AES1"), string((char *)hpExpected.getCipherType(0), 4));
    ASSERT_EQ(string("DH3k"), string((char *)hpExpected.getPubKeyType(0), 4));
    ASSERT_EQ(string("Mult"), string((char *)hpExpected.getPubKeyType(1), 4));
    ASSERT_EQ(string("B32 "), string((char *)hpExpected.getSasType(0), 4));
    ASSERT_EQ(string("HS32"), string((char *)hpExpected.getAuthLen(0), 4));
    ASSERT_EQ(string("HS80"), string((char *)hpExpected.getAuthLen(1), 4));
}

// No timeout happens in this test: Start and cancel timer must be in sync
TEST_F(ZrtpHelloTestFixture, check_timer_start_cancel) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    int32_t timers = 0;

    auto mockCallback = make_shared<testing::NiceMock<MockZrtpCallback>>();
    std::shared_ptr<ZrtpCallback> callback = mockCallback;      // perform implicit up-cast to base

    ON_CALL(*mockCallback, activateTimer).WillByDefault(DoAll(([&timers](int32_t time) { timers++; }), Return(1)));
    ON_CALL(*mockCallback, cancelTimer).WillByDefault(DoAll([&timers]() { timers--; }, Return(1)));

    ZRtp zrtp(aliceZid, callback, aliceId, configure, false, false);
    zrtp.startZrtpEngine();
    zrtp.stopZrtp();

    ASSERT_EQ(0, timers);
}

TEST_F(ZrtpHelloTestFixture, check_first_sent_Hello) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    auto mockCallback = make_shared<testing::NiceMock<MockZrtpCallback>>();
    std::shared_ptr<ZrtpCallback> callback = mockCallback;      // perform implicit up-cast to base

    uint8_t const * packetData;
    int32_t dataLength;

    EXPECT_CALL(*mockCallback, sendDataZRTP(_, _))
            .WillOnce(DoAll(testing::SaveArg<0>(&packetData), SaveArg<1>(&dataLength), Return(1)));

    EXPECT_CALL(*mockCallback, zrtpNegotiationFailed(_, _)).Times(0);

    ZRtp zrtp(aliceZid, callback, aliceId, configure, false, false);
    zrtp.startZrtpEngine();
    zrtp.stopZrtp();

    auto* header = (zrtpPacketHeader_t *)packetData;
    string packetType((char *)header->messageType, sizeof(header->messageType));
    ASSERT_EQ("Hello   ", packetType);

    ZrtpPacketHello hpExpected;
    hpExpected.configureHello(*configure);

    ZrtpPacketHello hp(packetData);         // packetData provides 4 bytes at the end for CRC, not computed by ZrtpPacketHello
    ASSERT_TRUE(hp.isLengthOk());   // if OK -> data parsing looks good

    ASSERT_EQ(hpExpected.getNumHashes(), hp.getNumHashes());
    ASSERT_EQ(hpExpected.getNumCiphers(), hp.getNumCiphers());
    ASSERT_EQ(hpExpected.getNumPubKeys(), hp.getNumPubKeys());
    ASSERT_EQ(hpExpected.getNumSas(), hp.getNumSas());
    ASSERT_EQ(hpExpected.getNumAuth(), hp.getNumAuth());

    ASSERT_EQ(string((char *)hpExpected.getHashType(0), 4), string((char *)hp.getHashType(0), 4));
    ASSERT_EQ(string((char *)hpExpected.getCipherType(0), 4), string((char *)hp.getCipherType(0), 4));
    ASSERT_EQ(string((char *)hpExpected.getPubKeyType(0), 4), string((char *)hp.getPubKeyType(0), 4));
    ASSERT_EQ(string((char *)hpExpected.getPubKeyType(1), 4), string((char *)hp.getPubKeyType(1), 4));
    ASSERT_EQ(string((char *)hpExpected.getSasType(0), 4), string((char *)hp.getSasType(0), 4));
    ASSERT_EQ(string((char *)hpExpected.getAuthLen(0), 4), string((char *)hp.getAuthLen(0), 4));
    ASSERT_EQ(string((char *)hpExpected.getAuthLen(1), 4), string((char *)hp.getAuthLen(1), 4));
}