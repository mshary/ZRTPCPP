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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <time.h>

#include <libzrtpcpp/ZIDRecordFile.h>

void ZIDRecordFile::setNewRs1(const unsigned char* data, int32_t expire) {

    // shift RS1 data into RS2 position
    memcpy(record.rs2Data, record.rs1Data, RS_LENGTH);
    memcpy(record.rs2Interval, record.rs1Interval, TIME_LENGTH);

    // set new RS1 data
    memcpy(record.rs1Data, data, RS_LENGTH);

    time_t validThru;
    if (expire == -1) {
        validThru = -1;
    }
    else if (expire <= 0) {
        validThru = 0;
    }
    else {
        validThru = time(nullptr) + expire;
    }

    if (sizeof(time_t) == 4) {
        long long temp = validThru;
        memcpy(record.rs1Interval, (unsigned char*)&temp, TIME_LENGTH);
    }
    else {
        memcpy(record.rs1Interval, (unsigned char*)&validThru, TIME_LENGTH);
    }
    resetRs2Valid();
    setRs1Valid();
}


bool ZIDRecordFile::isRs1NotExpired() {
    time_t current = time(nullptr);
    time_t validThru;

    if (sizeof(time_t) == 4) {
        long long temp;
        memcpy((unsigned char*)&temp, record.rs1Interval, TIME_LENGTH);
        validThru = temp;
    }
    else {
        memcpy((unsigned char*)&validThru, record.rs1Interval, TIME_LENGTH);
    }

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru);
}

bool ZIDRecordFile::isRs2NotExpired() {
    time_t current = time(NULL);
    time_t validThru;

    if (sizeof(time_t) == 4) {
        long long temp;
        memcpy((unsigned char*)&temp, record.rs2Interval, TIME_LENGTH);
        validThru = temp;
    }
    else {
        memcpy((unsigned char*)&validThru, record.rs2Interval, TIME_LENGTH);
    }

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru);
}

void ZIDRecordFile::setMiTMData(const unsigned char* data) {
    memcpy(record.mitmKey, data, RS_LENGTH);
    setMITMKeyAvailable();
}

void ZIDRecordFile::setZid(const unsigned char *zid) {
    memcpy(record.identifier, zid, IDENTIFIER_LEN);
}

void ZIDRecordFile::setRs1Valid()    { record.flags |= RS1Valid; }

void ZIDRecordFile::resetRs1Valid()  { record.flags &= ~RS1Valid; }

bool ZIDRecordFile::isRs1Valid()     { return ((record.flags & RS1Valid) == RS1Valid); }

void ZIDRecordFile::setRs2Valid()    { record.flags |= RS2Valid; }

void ZIDRecordFile::resetRs2Valid()  { record.flags &= ~RS2Valid; }

bool ZIDRecordFile::isRs2Valid()     { return ((record.flags & RS2Valid) == RS2Valid); }

void ZIDRecordFile::setMITMKeyAvailable()     { record.flags |= MITMKeyAvailable; }

void ZIDRecordFile::resetMITMKeyAvailable()   { record.flags &= ~MITMKeyAvailable; }

bool ZIDRecordFile::isMITMKeyAvailable()      { return ((record.flags & MITMKeyAvailable) == MITMKeyAvailable); }

void ZIDRecordFile::setOwnZIDRecord()   { record.flags = OwnZIDRecord; }

void ZIDRecordFile::resetOwnZIDRecord()  { record.flags = 0; }

bool ZIDRecordFile::isOwnZIDRecord()    { return (record.flags == OwnZIDRecord); }  // no other flag allowed if own ZID

void ZIDRecordFile::setSasVerified()    { record.flags |= SASVerified; }

void ZIDRecordFile::resetSasVerified()  { record.flags &= ~SASVerified; }

bool ZIDRecordFile::isSasVerified()     { return ((record.flags & SASVerified) == SASVerified); }

const uint8_t* ZIDRecordFile::getIdentifier()  {return record.identifier; }

const unsigned char* ZIDRecordFile::getRs1()   { return record.rs1Data; }

const unsigned char* ZIDRecordFile::getRs2()  { return record.rs2Data; }

const unsigned char* ZIDRecordFile::getMiTMData()  {return record.mitmKey; }

int ZIDRecordFile::getRecordType()  {return FILE_TYPE_RECORD; }

int64_t ZIDRecordFile::getSecureSince()  { return 0; }
