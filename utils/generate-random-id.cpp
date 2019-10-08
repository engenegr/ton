/* 
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission 
    to link the code of portions of this program with the OpenSSL library. 
    You must obey the GNU General Public License in all respects for all 
    of the code used other than OpenSSL. If you modify file(s) with this 
    exception, you may extend this exception to your version of the file(s), 
    but you are not obligated to do so. If you do not wish to do so, delete this 
    exception statement from your version. If you delete this exception statement 
    from all source files in the program, then also delete it here.

    Copyright 2017-2019 Telegram Systems LLP
*/
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cassert>
#include "crypto/ellcurve/Ed25519.h"
#include "adnl/utils.hpp"
#include "auto/tl/ton_api.h"
#include "auto/tl/ton_api_json.h"
#include "tl/tl_json.h"
#include "td/utils/OptionsParser.h"
#include "td/utils/filesystem.h"
#include "keys/encryptor.h"
#include "keys/keys.hpp"

extern "C" {
#include "sss.h"
#include "randombytes.h"
}
#include <cppcodec/base32_crockford.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_upper.hpp>
#include <termios.h>
#include <stdio.h>
#include <assert.h>
#include <cstdlib>

const int ALL_SHARES = 3;
const int THR_SHARES = 2;

void clear() {
    // CSI[2J clears screen, CSI[H moves the cursor to top-left corner
    std::cout << "\x1B[2J\x1B[H";
}


int main(int argc, char *argv[]) {
  ton::PrivateKey pk;
  ton::tl_object_ptr<ton::ton_api::adnl_addressList> addr_list;

  td::OptionsParser p;
  p.set_description("generate random id");

  std::string mode = "";

  std::string name = "id_ton";

  p.add_option('m', "mode", "sets mode id/adnl/dht/keys", [&](td::Slice key) {
    mode = key.str();
    return td::Status::OK();
  });
  p.add_option('h', "help", "prints_help", [&]() {
    char b[10240];
    td::StringBuilder sb(td::MutableSlice{b, 10000});
    sb << p;
    std::cout << sb.as_cslice().c_str();
    std::exit(2);
    return td::Status::OK();
  });
  p.add_option('n', "name", "name to keys", [&](td::Slice arg) {
    name = arg.str();
    return td::Status::OK();
  });
  p.add_option('k', "key", "private key to import", [&](td::Slice key) {
    if (!pk.empty()) {
      return td::Status::Error("duplicate '-k' option");
    }

    TRY_RESULT_PREFIX(data, td::read_file_secure(key.str()), "failed to read private key: ");
    TRY_RESULT_PREFIX_ASSIGN(pk, ton::PrivateKey::import(data.as_slice()), "failed to import private key: ");
    return td::Status::OK();
  });
  p.add_option('a', "addr-list", "addr list to sign", [&](td::Slice key) {
    if (addr_list) {
      return td::Status::Error("duplicate '-a' option");
    }
    CHECK(!addr_list);

    td::BufferSlice bs(key);
    TRY_RESULT_PREFIX(as_json_value, td::json_decode(bs.as_slice()), "bad addr list JSON: ");
    TRY_STATUS_PREFIX(td::from_json(addr_list, as_json_value), "bad addr list TL: ");
    return td::Status::OK();
  });
  p.add_option('s', "sss", "shamir secret sharing", [&](td::Slice arg) {
        if (!pk.empty()) {
            return td::Status::Error("key already initialized using another option");
        }
        std::string op_type = arg.str();
        if (op_type == "gen"){
            // Shamir secret sharing generation code
            if (pk.empty()) {
                pk = ton::privkeys::Ed25519::random();
            }
            using hex = cppcodec::hex_upper;
            uint8_t data[sss_MLEN];
            sss_Share shares[ALL_SHARES];

            std::string hex_slice = pk.export_as_slice().as_slice().remove_prefix(4).str(); 
            std::vector<uint8_t> uint_slice(hex_slice.begin(), hex_slice.end());

            for (unsigned i = 0; i < sizeof(data); ++i) {
                if(i < uint_slice.size()) {
                    data[i] = uint_slice[i];
                    continue;
                };
                data[i] = 0;
                // fill zeroes rest of the SSS message
            }
            // Split the secret into hares
            sss_create_shares(shares, data, ALL_SHARES, THR_SHARES);
            char response;
            for(int s=0; s<ALL_SHARES; ++s) {
                std::cout << "Are you ready to save key share #"<< s << " Y/n?" << std::endl;
                while(true) {
                    std::cin >> response;
                    if(response == 'y' || response == 'Y') {
                        clear();
                        break;
                    }
                }
                std::string shares_str = std::string(hex::encode(shares[s]));
                std::cout << "Share #"<< s << " size " << shares_str.size() << " " << shares_str << std::endl;
                std::cout << "Have you saved share #" << s << " Y/n?" << std::endl;
                while(true) {
                    std::cin >> response;
                    if(response == 'y' || response == 'Y') {
                        clear();
                        break;
                    }
                }
            }
            auto pub_key = pk.compute_public_key();
            auto short_key = pub_key.compute_short_id();
            std::cout << short_key.bits256_value().to_hex() << " " << td::base64_encode(short_key.as_slice()) << std::endl;
            using base64 = cppcodec::base64_rfc4648;
            
            std::string hex_pub_key = pub_key.export_as_slice().as_slice().str();
            std::vector<uint8_t> tmp_key(hex_pub_key.begin(), hex_pub_key.end());
            std::cout <<"pub key (base64-URL) "<< base64::encode(tmp_key) << std::endl;
            return td::Status::OK();
        } else if (op_type == "check") {
            // Shamir secret sharing check code
            uint8_t restored[sss_MLEN];
            sss_Share shares_decoded[THR_SHARES];
            using hex = cppcodec::hex_upper;
            int tmp;
            std::cout << "Testing shares " << " " << THR_SHARES << " of " << ALL_SHARES << std::endl;
            for (int idx = 0; idx < THR_SHARES; ++idx) {
                
                std::string user_input;
                std::cout << "Share " << idx << " input:"<< std::endl;

                struct termios oflags, nflags;
                char share_str[256];

                // disabling echo 
                tcgetattr(fileno(stdin), &oflags);
                nflags = oflags;
                nflags.c_lflag &= ~ECHO;
                nflags.c_lflag |= ECHONL;

                if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
                    perror("tcsetattr");
                    return td::Status::Error("input error");
                }

                fgets(share_str, sizeof(share_str), stdin);
                share_str[strlen(share_str) - 1] = 0;

                // restore terminal 
                if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
                    perror("tcsetattr");
                    return td::Status::Error("input error");
                };
                std::vector<uint8_t> tmp_share(sss_SHARE_LEN);
                tmp_share = hex::decode(share_str);
                for (int i=0; i < sss_SHARE_LEN; ++i)
                {
                    shares_decoded[idx][i] = tmp_share[i];
                };
            };   
            // Combine some of the shares to restore the original secret
            tmp = sss_combine_shares(restored, shares_decoded, 2);
            if (tmp != 0) {
                std::cerr << "Shared secret wasn't restored successfully. Closing." << std::endl;
                return td::Status::Error("key reconstruction error");
            }
            // exctract Ed25519 key
            char restored_ch[32];
            for (unsigned i = 0; i < sizeof(restored_ch); ++i) {
                restored_ch[i] = (unsigned char)restored[i];
            }
            // using TON stuff for importing key 
            td::MutableSlice secret(restored_ch, sizeof(restored_ch));
            td::SecureString key_string{36};
            auto id = ton::ton_api::pk_ed25519::ID;
            key_string.as_mutable_slice().copy_from(td::Slice{reinterpret_cast<const td::uint8 *>(&id), 4});
            key_string.as_mutable_slice().remove_prefix(4).copy_from(secret);
            TRY_RESULT_PREFIX_ASSIGN(pk, ton::PrivateKey::import(key_string), "failed to import private key: ");   
            auto pub_key = pk.compute_public_key();
            auto short_key = pub_key.compute_short_id();
            std::cout << short_key.bits256_value().to_hex() << " " << td::base64_encode(short_key.as_slice()) << std::endl;
            return td::Status::OK();
    }
    return td::Status::OK();
  });

  auto S = p.run(argc, argv);

  if (S.is_error()) {
    std::cerr << S.move_as_error().message().str() << std::endl;
    return 2;
  }

  if (mode.size() == 0) {
    std::cerr << "'-m' option missing" << std::endl;
    return 2;
  }

  if (pk.empty()) {
    pk = ton::privkeys::Ed25519::random();
  } else {
    std::cout << "Key is not empty (SSS). Closing" << std::endl;
    return 0;      
  }

  auto pub_key = pk.compute_public_key();
  auto short_key = pub_key.compute_short_id();

  if (mode == "id") {
    std::string v;
    v = td::json_encode<std::string>(td::ToJson(pk.tl()));
    std::cout << v << std::endl;
    v = td::json_encode<std::string>(td::ToJson(pub_key.tl()));
    std::cout << v << std::endl;
    v = td::json_encode<std::string>(td::ToJson(ton::adnl::AdnlNodeIdShort{short_key}.tl()));
    std::cout << v << std::endl;
  } else if (mode == "adnl") {
    if (!addr_list) {
      std::cerr << "'-a' option missing" << std::endl;
      return 2;
    }
    auto x = ton::create_tl_object<ton::ton_api::adnl_node>(pub_key.tl(), std::move(addr_list));
    auto e = pk.create_decryptor().move_as_ok();
    auto r = e->sign(ton::serialize_tl_object(x, true).as_slice()).move_as_ok();

    auto v = td::json_encode<std::string>(td::ToJson(x));
    std::cout << v << std::endl;
  } else if (mode == "dht") {
    if (!addr_list) {
      std::cerr << "'-a' option missing" << std::endl;
      return 2;
    }
    auto x = ton::create_tl_object<ton::ton_api::dht_node>(pub_key.tl(), std::move(addr_list), -1, td::BufferSlice());
    auto e = pk.create_decryptor().move_as_ok();
    auto r = e->sign(ton::serialize_tl_object(x, true).as_slice()).move_as_ok();
    x->signature_ = std::move(r);

    auto v = td::json_encode<std::string>(td::ToJson(x));
    std::cout << v << "\n";
  } else if (mode == "keys") {
    td::write_file(name, pk.export_as_slice()).ensure();
    td::write_file(name + ".pub", pub_key.export_as_slice().as_slice()).ensure();

    std::cout << short_key.bits256_value().to_hex() << " " << td::base64_encode(short_key.as_slice()) << std::endl;
  } else {
    std::cerr << "unknown mode " << mode;
    return 2;
  }
  return 0;
}
