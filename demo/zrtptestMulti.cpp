/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Test ZRTP extension for ccRTP

#include <cstdlib>
#include <map>
#include <zrtpccrtp.h>
#include <libzrtpcpp/ZrtpUserCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <zrtp/libzrtpcpp/ZIDCacheFile.h>

using namespace ost;
using namespace std;
using namespace GnuZrtpCodes;

class PacketsPattern {
public:
    inline const InetHostAddress &
    getDestinationAddress() const {
        return destinationAddress;
    }

    inline tpport_t
    getDestinationPort() const {
        return destinationPort;
    }

    uint32
    getPacketsNumber() const {
        return packetsNumber;
    }

    uint32
    getSsrc() const {
        return 0xdeadbeef;
    }

    static const unsigned char *
    getPacketData(uint32 i) {
        return data[i % 2];
    }

    static size_t
    getPacketSize(uint32 i) {
        return strlen((char *) data[i % 2]) + 1;
    }

private:
    static const InetHostAddress destinationAddress;
    static const uint16 destinationPort = 5002;
    static const uint32 packetsNumber = 10;
    static const unsigned char *data[];
};

const InetHostAddress PacketsPattern::destinationAddress = InetHostAddress("localhost");

const unsigned char *PacketsPattern::data[] = {
        (unsigned char *) "0123456789\n",
        (unsigned char *) "987654321\n"
};

PacketsPattern pattern;

class ZrtpRecvPacketTransmissionTestCB;

class ZrtpSendPacketTransmissionTestCB;

class MyUserCallback;

class MyUserCallbackMulti;

static ZrtpRecvPacketTransmissionTestCB *zrxcb = nullptr;
static ZrtpSendPacketTransmissionTestCB *ztxcb = nullptr;

static ZrtpRecvPacketTransmissionTestCB *zrxcbMulti = nullptr;
static ZrtpSendPacketTransmissionTestCB *ztxcbMulti = nullptr;

static bool enroll = false;
static bool mitm = false;
static bool untrusted = false;
static bool sender = false;
static bool recver = false;
static bool signsas = false;


/**
 * SymmetricZRTPSession in security mode and using a callback class.
 *
 * The next two classes show how to use <code>SymmetricZRTPSession</code>
 * using the standard ZRTP handshake an switching to encrypted (SRTP) mode.
 * The application enables this by calling <code>initialize(...)</code>.
 * In addition the application sets a callback class (see above). ZRTP calls
 * the methods of the callback class and the application may implement
 * appropriate methods to deal with these triggers.
 */

class ZrtpSendPacketTransmissionTestCB : public Thread, public TimerPort {

private:
    SymmetricZRTPSession *tx;
    string multiParams;
    string prefix;
    ZRtp *zrtpMaster = nullptr;

public:

    ZrtpSendPacketTransmissionTestCB() : tx(nullptr), multiParams("") {};

    void run() override {
        doTest();
    }

    int doTest();

    string getMultiStrParams() {
        return tx->getMultiStrParams(&zrtpMaster);
    }

    void setMultiStrParams(string params, ZRtp *zrtpM) {
        multiParams = move(params);
        zrtpMaster = zrtpM;
    }
};


class ZrtpRecvPacketTransmissionTestCB : public Thread {

private:
    SymmetricZRTPSession *rx;
    string multiParams;
    string prefix;
    ZRtp *zrtpMaster = nullptr;

public:
    ZrtpRecvPacketTransmissionTestCB() : rx(nullptr), multiParams("") {};

    void run() override {
        doTest();
    }

    int doTest();

    string getMultiStrParams() {
        return rx->getMultiStrParams(&zrtpMaster);
    }

    void setMultiStrParams(string params, ZRtp *zrtpM) {
        multiParams = move(params);
        zrtpMaster = zrtpM;
    }
};

/**
 * Simple User Callback class
 *
 * This class overwrite some methods from ZrtpUserCallback to get information
 * about ZRTP processing and information about ZRTP results. The standard
 * implementation of this class just perform return, thus effectively
 * supressing any callback or trigger.
 */
class MyUserCallback : public ZrtpUserCallback {

protected:
    static map<int32, std::string *> infoMap;
    static map<int32, std::string *> warningMap;
    static map<int32, std::string *> severeMap;
    static map<int32, std::string *> zrtpMap;
    static map<int32, std::string *> enrollMap;


    static bool initialized;

    SymmetricZRTPSession *session;

    std::string prefix;

public:
    explicit MyUserCallback(SymmetricZRTPSession *s) : session(s), prefix("default: ") {

        if (initialized) {
            return;
        }
        infoMap.insert(pair<int32, std::string *>(InfoHelloReceived, new string("Hello received, preparing a Commit")));
        infoMap.insert(
                pair<int32, std::string *>(InfoCommitDHGenerated, new string("Commit: Generated a public DH key")));
        infoMap.insert(pair<int32, std::string *>(InfoRespCommitReceived,
                                                  new string("Responder: Commit received, preparing DHPart1")));
        infoMap.insert(
                pair<int32, std::string *>(InfoDH1DHGenerated, new string("DH1Part: Generated a public DH key")));
        infoMap.insert(pair<int32, std::string *>(InfoInitDH1Received,
                                                  new string("Initiator: DHPart1 received, preparing DHPart2")));
        infoMap.insert(pair<int32, std::string *>(InfoRespDH2Received,
                                                  new string("Responder: DHPart2 received, preparing Confirm1")));
        infoMap.insert(pair<int32, std::string *>(InfoInitConf1Received,
                                                  new string("Initiator: Confirm1 received, preparing Confirm2")));
        infoMap.insert(pair<int32, std::string *>(InfoRespConf2Received,
                                                  new string("Responder: Confirm2 received, preparing Conf2Ack")));
        infoMap.insert(pair<int32, std::string *>(InfoRSMatchFound,
                                                  new string("At least one retained secrets matches - security OK")));
        infoMap.insert(pair<int32, std::string *>(InfoSecureStateOn, new string("Entered secure state")));
        infoMap.insert(pair<int32, std::string *>(InfoSecureStateOff, new string("No more security for this session")));

        warningMap.insert(pair<int32, std::string *>(WarningDHAESmismatch,
                                                     new string(
                                                             "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096")));
        warningMap.insert(pair<int32, std::string *>(WarningGoClearReceived, new string("Received a GoClear message")));
        warningMap.insert(pair<int32, std::string *>(WarningDHShort,
                                                     new string(
                                                             "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096")));
        warningMap.insert(
                pair<int32, std::string *>(WarningNoRSMatch, new string("No retained secret matches - verify SAS")));
        warningMap.insert(pair<int32, std::string *>(WarningCRCmismatch, new string(
                "Internal ZRTP packet checksum mismatch - packet dropped")));
        warningMap.insert(pair<int32, std::string *>(WarningSRTPauthError, new string(
                "Dropping packet because SRTP authentication failed!")));
        warningMap.insert(pair<int32, std::string *>(WarningSRTPreplayError,
                                                     new string("Dropping packet because SRTP replay check failed!")));
        warningMap.insert(pair<int32, std::string *>(WarningNoExpectedRSMatch,
                                                     new string(
                                                             "Valid retained shared secrets availabe but no matches found - must verify SAS")));

        severeMap.insert(
                pair<int32, std::string *>(SevereHelloHMACFailed, new string("Hash HMAC check of Hello failed!")));
        severeMap.insert(
                pair<int32, std::string *>(SevereCommitHMACFailed, new string("Hash HMAC check of Commit failed!")));
        severeMap.insert(
                pair<int32, std::string *>(SevereDH1HMACFailed, new string("Hash HMAC check of DHPart1 failed!")));
        severeMap.insert(
                pair<int32, std::string *>(SevereDH2HMACFailed, new string("Hash HMAC check of DHPart2 failed!")));
        severeMap.insert(pair<int32, std::string *>(SevereCannotSend,
                                                    new string("Cannot send data - connection or peer down?")));
        severeMap.insert(
                pair<int32, std::string *>(SevereProtocolError, new string("Internal protocol error occured!")));
        severeMap.insert(pair<int32, std::string *>(SevereNoTimer, new string(
                "Cannot start a timer - internal resources exhausted?")));
        severeMap.insert(pair<int32, std::string *>(SevereTooMuchRetries,
                                                    new string(
                                                            "Too much retries during ZRTP negotiation - connection or peer down?")));

        zrtpMap.insert(pair<int32, std::string *>(MalformedPacket,
                                                  new string("Malformed packet (CRC OK, but wrong structure)")));
        zrtpMap.insert(pair<int32, std::string *>(CriticalSWError, new string("Critical software error")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppZRTPVersion, new string("Unsupported ZRTP version")));
        zrtpMap.insert(pair<int32, std::string *>(HelloCompMismatch, new string("Hello components mismatch")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppHashType, new string("Hash type not supported")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppCiphertype, new string("Cipher type not supported")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppPKExchange, new string("Public key exchange not supported")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppSRTPAuthTag, new string("SRTP auth. tag not supported")));
        zrtpMap.insert(pair<int32, std::string *>(UnsuppSASScheme, new string("SAS scheme not supported")));
        zrtpMap.insert(
                pair<int32, std::string *>(NoSharedSecret, new string("No shared secret available, DH mode required")));
        zrtpMap.insert(
                pair<int32, std::string *>(DHErrorWrongPV, new string("DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
        zrtpMap.insert(pair<int32, std::string *>(DHErrorWrongHVI, new string("DH Error: hvi != hashed data")));
        zrtpMap.insert(
                pair<int32, std::string *>(SASuntrustedMiTM, new string("Received relayed SAS from untrusted MiTM")));
        zrtpMap.insert(pair<int32, std::string *>(ConfirmHMACWrong, new string("Auth. Error: Bad Confirm pkt HMAC")));
        zrtpMap.insert(pair<int32, std::string *>(NonceReused, new string("Nonce reuse")));
        zrtpMap.insert(pair<int32, std::string *>(EqualZIDHello, new string("Equal ZIDs in Hello")));
        zrtpMap.insert(
                pair<int32, std::string *>(GoCleatNotAllowed, new string("GoClear packet received, but not allowed")));

        enrollMap.insert(
                pair<int32, std::string *>(EnrollmentRequest, new string("Trusted MitM enrollment requested")));
        enrollMap.insert(
                pair<int32, std::string *>(EnrollmentCanceled, new string("Trusted MitM enrollment canceled by user")));
        enrollMap.insert(pair<int32, std::string *>(EnrollmentFailed, new string("Trusted MitM enrollment failed")));
        enrollMap.insert(pair<int32, std::string *>(EnrollmentOk, new string("Trusted MitM enrollment OK")));

        initialized = true;
    }

    void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) override {
        string *msg;
        uint8_t sasHash[32];

        if (sev == Info) {
            msg = infoMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
            // this sets up and starts off the multi-stream test
            if (subCode == InfoSecureStateOn) {
                ZRtp *zrtpMaster = nullptr;
                std::string str;
                if (zrxcbMulti != nullptr) {
                    str = session->getMultiStrParams(&zrtpMaster);
                    zrxcbMulti->setMultiStrParams(str, zrtpMaster);
                    fprintf(stderr, "Master (test r): %p\n", static_cast<void *>(zrtpMaster));
                    zrxcbMulti->start();
                }
                if (ztxcbMulti != nullptr) {
                    str = session->getMultiStrParams(&zrtpMaster);
                    ztxcbMulti->setMultiStrParams(str, zrtpMaster);
                    fprintf(stderr, "Master (test t): %p\n", static_cast<void *>(zrtpMaster));
                    ztxcbMulti->start();
                }
                if (sender) {
                    if (mitm && !enroll) {  // sender now acts as trusted PBX in normal mode, not in enrollement service
                        std::string render = session->getSasType();
                        for (unsigned char &i : sasHash) {
                            i = 0;
                        }
                        if (untrusted) {    // treat receiver as non-enrolled receiver
                            cout << prefix << "send SAS relay to non-enrolled receiver" << endl;
                            session->sendSASRelayPacket(sasHash, render);
                        } else {
                            sasHash[0] = 0x11;
                            sasHash[1] = 0x22;
                            sasHash[2] = 0x33;
                            sasHash[4] = 0x44;
                            cout << prefix << "send SAS relay to enrolled receiver" << endl;
                            session->sendSASRelayPacket(sasHash, render);
                        }
                    }
                }
            }
        }
        if (sev == Warning) {
            msg = warningMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
        if (sev == Severe) {
            msg = severeMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
        if (sev == ZrtpError) {
            if (subCode < 0) {  // received an error packet from peer
                subCode *= -1;
                cout << prefix << "Received error packet: ";
            } else {
                cout << prefix << "Sent error packet: ";
            }
            msg = zrtpMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
    }

    void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) override {
        string *msg;
        if (sev == ZrtpError) {
            if (subCode < 0) {  // received an error packet from peer
                subCode *= -1;
                cout << prefix << "Received error packet: ";
            } else {
                cout << prefix << "Sent error packet: ";
            }
            msg = zrtpMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        } else {
            msg = severeMap[subCode];
            cout << prefix << *msg << endl;
        }
    }

    void zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info) override {
        string *msg = enrollMap[info];
        cout << prefix << *msg << endl;
        session->acceptEnrollment(true);
    }

    void zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment info) override {
        string *msg = enrollMap[info];
        cout << prefix << *msg << endl;
    }

    void secureOn(std::string cipher) override {
        cout << prefix << "Using cipher:" << cipher << endl;
        cout << prefix << "peer hello hash: " << session->getPeerHelloHash() << endl;
    }

    void showSAS(std::string sas, bool verified) override {
        cout << prefix << "SAS is: " << sas << endl;

    }

    void signSAS(uint8_t *sasHash) override {
        cout << prefix << "SAS to sign" << endl;
        uint8_t sign[12];
        sign[0] = sasHash[0];
        sign[1] = sasHash[1];
        sign[2] = sasHash[2];
        sign[3] = sasHash[3];
        if (recver) {
            sign[4] = 'R';
            sign[5] = 'E';
            sign[6] = 'C';
            sign[7] = 'E';
            sign[8] = 'I';
            sign[9] = 'V';
            sign[10] = 'E';
            sign[11] = 'R';
        } else {
            sign[4] = 'T';
            sign[5] = 'R';
            sign[6] = 'A';
            sign[7] = 'N';
            sign[8] = 'S';
            sign[9] = 'M';
            sign[10] = 'I';
            sign[11] = 'T';
        }
        cout << prefix << "set signature data result: " << session->setSignatureData(sign, 12) << endl;
    }

    bool checkSASSignature(uint8_t *sasHash) override {
        cout << prefix << "check signature" << endl;
        const uint8_t *sign = session->getSignatureData();
        cout << prefix << "signature: " << sign << endl;
        return true;
    }

    void setPrefix(std::string p) {
        prefix = move(p);
    }
};

map<int32, std::string *>MyUserCallback::infoMap;
map<int32, std::string *>MyUserCallback::warningMap;
map<int32, std::string *>MyUserCallback::severeMap;
map<int32, std::string *>MyUserCallback::zrtpMap;
map<int32, std::string *>MyUserCallback::enrollMap;

bool MyUserCallback::initialized = false;


class MyUserCallbackMulti : public MyUserCallback {

public:

    explicit MyUserCallbackMulti(SymmetricZRTPSession *s) : MyUserCallback(s) {
    }

    void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) override {
        string *msg;
        if (sev == Info) {
            msg = infoMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
        if (sev == Warning) {
            msg = warningMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
        if (sev == Severe) {
            msg = severeMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
        if (sev == ZrtpError) {
            if (subCode < 0) {  // received an error packet from peer
                subCode *= -1;
                cout << prefix << "Received error packet: ";
            } else {
                cout << prefix << "Sent error packet: ";
            }
            msg = zrtpMap[subCode];
            if (msg != nullptr) {
                cout << prefix << *msg << endl;
            }
        }
    }
};

static std::shared_ptr<ZIDCache> zrtpCache = nullptr;

static std::shared_ptr<ZIDCache>
initCache(const char *zidFilename, std::shared_ptr<ZIDCache> cache) {
    std::string fname;
    if (!zidFilename) {
        char *home = getenv("HOME");
        std::string baseDir = (home) ? (std::string(home) + std::string("/."))
                                     : std::string(".");
        fname = baseDir + std::string("GNUZRTP.zid");
        zidFilename = fname.c_str();
    }

    // Check if a cache is available.
    // If yes and it has the same filename -> use it
    // otherwise close file and open new cache file
    if (cache) {
        if (cache->getFileName() == zidFilename) {
            return cache;
        }
        cache->close();
        if (cache->open((char *) zidFilename) < 0) {
            return std::shared_ptr<ZIDCache>();
        }
        return cache;
    }

    auto zf = std::make_shared<ZIDCacheFile>();
    if (zf->open((char *) zidFilename) < 0) {
        return std::shared_ptr<ZIDCache>();
    }
    return zf;
}

int ZrtpSendPacketTransmissionTestCB::doTest() {

    std::shared_ptr<ZrtpConfigure> config;

    MyUserCallback *mcb;
    if (!multiParams.empty()) {
        tx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                      pattern.getDestinationPort() + 2 + 10);

        tx->initialize("test_t.zid", true, config);
        // tx->initialize("test_t.zid", true);
        tx->setMultiStrParams(multiParams, zrtpMaster);

        prefix = "TX Multi: ";
        mcb = new MyUserCallbackMulti(tx);
        mcb->setPrefix(prefix);
    } else {
        tx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                      pattern.getDestinationPort() + 2);
        if (mitm) {                      // Act as trusted MitM - could be enrolled
            tx->setMitmMode(true);
        }

        tx->setSignSas(signsas);
        tx->initialize("test_t.zid", true, config);
        // tx->initialize("test_t.zid", true);

        if (enroll)                     // act as PBX enrollement service
            tx->setEnrollmentMode(true);

        prefix = "TX: ";
        mcb = new MyUserCallback(tx);
        mcb->setPrefix(prefix);
    }
    // At this point the Hello hash is available. See ZRTP specification
    // chapter 9.1 for further information when an how to use the Hello
    // hash.
    int numSupportedVersion = tx->getNumberSupportedVersions();
    cout << "TX Hello hash 0: " << tx->getHelloHash(0) << endl;
    cout << "TX Hello hash 0 length: " << tx->getHelloHash(0).length() << endl;
    if (numSupportedVersion > 1) {
        cout << "TX Hello hash 1: " << tx->getHelloHash(1) << endl;
        cout << "TX Hello hash 1 length: " << tx->getHelloHash(1).length() << endl;
    }
    tx->setUserCallback(mcb);
    tx->setSchedulingTimeout(10000);
    tx->setExpireTimeout(1000000);

    tx->startRunning();

    tx->setPayloadFormat(StaticPayloadFormat(sptPCMU));

    if (!multiParams.empty()) {
        if (!tx->addDestination(pattern.getDestinationAddress(),
                                pattern.getDestinationPort() + 10)) {
            return 1;
        }
    } else {
        if (!tx->addDestination(pattern.getDestinationAddress(),
                                pattern.getDestinationPort())) {
            return 1;
        }
    }
    tx->startZrtp();

    // 2 packets per second (packet duration of 500ms)
    uint32 period = 500;
    uint16 inc = tx->getCurrentRTPClockRate() / 2;
    TimerPort::setTimer(period);
    uint32 i;
    for (i = 0; i < pattern.getPacketsNumber(); i++) {
        tx->putData(i * inc,
                    PacketsPattern::getPacketData(i),
                    PacketsPattern::getPacketSize(i));
        cout << prefix << "Sent some data: " << i << endl;
        Thread::sleep(TimerPort::getTimer());
        TimerPort::incTimer(period);
    }
    tx->putData(i * inc, (unsigned char *) "exit", 5);
    Thread::sleep(TimerPort::getTimer());
    delete tx;
    return 0;
}


int ZrtpRecvPacketTransmissionTestCB::doTest() {

    std::shared_ptr<ZrtpConfigure> config;

    MyUserCallback *mcb;
    if (!multiParams.empty()) {
        rx = new SymmetricZRTPSession(pattern.getDestinationAddress(), pattern.getDestinationPort() + 10);

        rx->initialize("test_r.zid", true, config);
        // rx->initialize("test_r.zid", true);
        rx->setMultiStrParams(multiParams, zrtpMaster);

        prefix = "RX Multi: ";
        mcb = new MyUserCallbackMulti(rx);
        mcb->setPrefix(prefix);
    } else {
        rx = new SymmetricZRTPSession(pattern.getDestinationAddress(), pattern.getDestinationPort());
        auto zf = initCache("test_r.zid", zrtpCache);
        if (!zf) {
            return -1;
        }
        if (!zrtpCache) {
            zrtpCache = zf;
        }

        config = std::make_shared<ZrtpConfigure>();
        config->setZidCache(zf);
        config->setStandardConfig();

//        config.clear();
//        config.addAlgo(SasType, zrtpSasTypes.getByName("B256"));

        if (enroll)
            config->setTrustedMitM(true);                // allow a trusted MitM to start enrollment process

        rx->setSignSas(signsas);

        rx->initialize("test_r.zid", true, config);
//            rx->initialize("test_r.zid", true);

        prefix = "RX: ";
        mcb = new MyUserCallback(rx);
        mcb->setPrefix(prefix);
    }
    // At this point the Hello hash is available. See ZRTP specification
    // chapter 9.1 for further information when an how to use the Hello
    // hash.
    int numSupportedVersion = rx->getNumberSupportedVersions();
    cout << "RX Hello hash 0: " << rx->getHelloHash(0) << endl;
    cout << "RX Hello hash 0 length: " << rx->getHelloHash(0).length() << endl;
    if (numSupportedVersion > 1) {
        cout << "RX Hello hash 1: " << rx->getHelloHash(1) << endl;
        cout << "RX Hello hash 1 length: " << rx->getHelloHash(1).length() << endl;
    }
    rx->setUserCallback(mcb);
    rx->setSchedulingTimeout(10000);
    rx->setExpireTimeout(1000000);

    rx->startRunning();
    rx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
    // arbitrary number of loops to provide time to start transmitter
    if (!multiParams.empty()) {
        if (!rx->addDestination(pattern.getDestinationAddress(), pattern.getDestinationPort() + 2 + 10)) {
            return 1;
        }
    } else {
        if (!rx->addDestination(pattern.getDestinationAddress(), pattern.getDestinationPort() + 2)) {
            return 1;
        }
    }
//        rx->startZrtp();

    for (int i = 0; i < 5000; i++) {
        const AppDataUnit *adu;
        while ((adu = rx->getData(rx->getFirstTimestamp()))) {
            cerr << prefix << "got some data: " << adu->getData() << endl;
            if (*adu->getData() == 'e') {
                delete adu;
                delete rx;
                return 0;
            }
            delete adu;
        }
        Thread::sleep(70);
    }
    delete rx;
    return 0;
}


int main(int argc, char *argv[]) {
    int result = 0;

    char c;

    /* check args */
    while (true) {
        c = getopt(argc, argv, "rsSmeu");
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'r':
                recver = true;
                break;
            case 's':
                sender = true;
                break;
            case 'm':
                mitm = true;
                break;
            case 'e':
                enroll = true;
                break;
            case 'u':
                untrusted = true;
                break;
            case 'S':
                signsas = true;
                break;
            default:
                cerr << "Wrong Arguments, only -s and -r are accepted" << endl;
        }
    }

    if (sender || recver) {
        if (sender) {
            cout << "Running as sender" << endl;
        } else {
            cout << "Running as receiver" << endl;
        }
    } else {
        cerr << "No send or receive argument specified" << endl;
        exit(1);
    }

    if (sender) {
        ztxcb = new ZrtpSendPacketTransmissionTestCB();
        ztxcbMulti = new ZrtpSendPacketTransmissionTestCB();
        ztxcb->start();
        ztxcb->join();
        ztxcbMulti->join();
    } else if (recver) {
        zrxcb = new ZrtpRecvPacketTransmissionTestCB();
        zrxcbMulti = new ZrtpRecvPacketTransmissionTestCB();
        zrxcb->start();
        zrxcb->join();
        zrxcbMulti->join();
    }

    exit(result);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
