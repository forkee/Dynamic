DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

DYNAMIC_CONFIG_INCLUDES=-I$(builddir)/config
DYNAMIC_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

DYNAMIC_INCLUDES += -I$(srcdir)/secp256k1/include
DYNAMIC_INCLUDES += -I$(srcdir)/univalue/include

LIBDYNAMIC_SERVER=libdynamic_server.a
LIBDYNAMIC_WALLET=libdynamic_wallet.a
LIBDYNAMIC_COMMON=libdynamic_common.a
LIBDYNAMIC_CLI=libdynamic_cli.a
LIBDYNAMIC_UTIL=libdynamic_util.a
LIBDYNAMIC_CRYPTO=crypto/libdynamic_crypto.a
LIBDYNAMICQT=qt/libdynamicqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBUNIVALUE=univalue/libunivalue.la
LIBCRYPTOPP=cryptopp/libcryptopp.a

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBCRYPTOPP):
	@echo "Building CryptoPP Cryptographic Library..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" CC="$(CC)" OPT="$(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS)"

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  crypto/libdynamic_crypto.a \
  libdynamic_util.a \
  libdynamic_common.a \
  libdynamic_server.a \
  libdynamic_cli.a
  
if ENABLE_WALLET
DYNAMIC_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += libdynamic_wallet.a
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += libdynamic_zmq.a
endif

if BUILD_DYNAMIC_LIBS
lib_LTLIBRARIES = libdynamicconsensus.la
LIBDYNAMIC_CONSENSUS=libdynamicconsensus.la
else
LIBDYNAMIC_CONSENSUS=
endif

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_DYNAMICD
  bin_PROGRAMS += dynamicd
endif

if BUILD_DYNAMIC_UTILS
  bin_PROGRAMS += dynamic-cli
#dynamic-tx
endif

.PHONY: FORCE check-symbols check-security
# dynamic #
DYNAMIC_CORE_H = \
  protocol/ntp.h \
  protocol/identity.h \
  protocol/cert.h \
  protocol/escrow.h \
  protocol/feedback.h \
  protocol/messagecrypter.h \
  protocol/message.h \
  protocol/offer.h \
  protocol/fluid.h \
  protocol/duality.h \
  protocol/auxillary.h \
  activedynode.h \
  addressindex.h \
  spentindex.h \
  addrman.h \
  alert.h \
  amount.h \
  arith_uint256.h \
  base58.h \
  bip39_english.h \
  bip39.h \
  bloom.h \
  cachemap.h \
  cachemultimap.h \
  chain.h \
  chainparams.h \
  checkforks.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  dbwrapper.h \
  dynode.h \
  dynode-payments.h \
  dynode-sync.h \
  dynodeman.h \
  dynodeconfig.h \
  flat-database.h \
  governance.h \
  governance-classes.h \
  governance-exceptions.h \
  governance-object.h \
  governance-vote.h \
  governance-votedb.h \
  hash.h \
  hdchain.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  instantsend.h \
  key.h \
  keepass.h \
  keystore.h \
  limitedmap.h \
  main.h \
  memusage.h \
  merkleblock.h \
  messagesigner.h \
  miner.h \
  net.h \
  netbase.h \
  netfulfilledman.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  privatesend.h \
  psnotificationinterface.h \
  privatesend-relay.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpcclient.h \
  rpcprotocol.h \
  rpcserver.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  serialize.h \
  spork.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/lockedpool.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltime.h \
  validationinterface.h \
  version.h \
  versionbits.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libdynamic_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between dynamicd and dynamic-qt
libdynamic_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libdynamic_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_server_a_SOURCES = \
  protocol/ntp.cpp \
  protocol/identity.cpp \
  protocol/cert.cpp \
  protocol/escrow.cpp \
  protocol/message.cpp \
  protocol/messagecrypter.cpp \
  protocol/offer.cpp \
  protocol/fluid.cpp \
  protocol/duality.cpp \
  protocol/auxillary.cpp \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  checkforks.cpp \
  dbwrapper.cpp \
  governance.cpp \
  governance-classes.cpp \
  governance-object.cpp \
  governance-vote.cpp \
  governance-votedb.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  main.cpp \
  merkleblock.cpp \
  messagesigner.cpp \
  miner.cpp \
  net.cpp \
  netfulfilledman.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpcblockchain.cpp \
  rpcdynode.cpp \
  rpcgovernance.cpp \
  rpcmining.cpp \
  rpcmisc.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcserver.cpp \
  protocol/rpcfluid.cpp \
  script/sigcache.cpp \
  sendalert.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(DYNAMIC_CORE_H)

if ENABLE_ZMQ
LIBDYNAMIC_ZMQ=libdynamic_zmq.a

libdynamic_zmq_a_CPPFLAGS = $(DYNAMIC_INCLUDES) $(ZMQ_CFLAGS)
libdynamic_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between dynamicd and dynamic-qt, but only linked
# when wallet enabled
libdynamic_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
libdynamic_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_wallet_a_SOURCES = \
  activedynode.cpp \
  dynode.cpp \
  dynode-payments.cpp \
  dynode-sync.cpp \
  dynodeconfig.cpp \
  dynodeman.cpp \
  instantsend.cpp \
  keepass.cpp \
  policy/rbf.cpp \
  privatesend.cpp \
  privatesend-relay.cpp \
  psnotificationinterface.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(DYNAMIC_CORE_H)

# crypto primitives library
crypto_libdynamic_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_CONFIG_INCLUDES) $(PIC_FLAGS)
crypto_libdynamic_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS)
crypto_libdynamic_crypto_a_SOURCES = \
	crypto/argon2d/argon2.c \
	crypto/argon2d/argon2.h \
	crypto/argon2d/core.c \
	crypto/argon2d/core.h \
	crypto/argon2d/encoding.c \
	crypto/argon2d/encoding.h \
	crypto/argon2d/opt.c \
	crypto/argon2d/thread.c \
	crypto/argon2d/thread.h \
	crypto/blake2/blake2-impl.h \
	crypto/blake2/blake2.h \
	crypto/blake2/blake2b.c \
	crypto/blake2/blamka-round-opt.h \
	crypto/blake2/blamka-round-ref.h \
	crypto/common.h \
	crypto/chacha20.cpp \
	crypto/chacha20.h \
	crypto/hmac_sha256.cpp \
	crypto/hmac_sha256.h \
	crypto/hmac_sha512.cpp \
	crypto/hmac_sha512.h \
	crypto/muhash.cpp \
	crypto/muhash.h \
	crypto/ripemd160.cpp \
	crypto/ripemd160.h \
	crypto/sha1.cpp \
	crypto/sha1.h \
	crypto/sha256.cpp \
	crypto/sha256.h \
	crypto/sha512.cpp \
	crypto/sha512.h \
	protocol/libs/aes_helper.c \
	protocol/libs/sha3nist.h \
	protocol/libs/blake.c \
	protocol/libs/sph_blake.h \
	protocol/libs/bmw.c \
	protocol/libs/sph_bmw.h \
	protocol/libs/cubehash.c \
	protocol/libs/sph_cubehash.h \
	protocol/libs/echo.c \
	protocol/libs/sph_echo.h \
	protocol/libs/fugue.c \
	protocol/libs/sph_fugue.h \
	protocol/libs/groestl.c \
	protocol/libs/sph_groestl.h \
	protocol/libs/hamsi.c \
	protocol/libs/sph_hamsi.h \
	protocol/libs/haval.c \
	protocol/libs/sph_haval.h \
	protocol/libs/jh.c \
	protocol/libs/sph_jh.h \
	protocol/libs/keccak.c \
	protocol/libs/sph_keccak.h \
	protocol/libs/luffa.c \
	protocol/libs/sph_luffa.h \
	protocol/libs/md2.c \
	protocol/libs/sph_md2.h \
	protocol/libs/md4.c \
	protocol/libs/sph_md4.h \
	protocol/libs/md5.c \
	protocol/libs/sph_md5.h \
	protocol/libs/panama.c \
	protocol/libs/sph_panama.h \
	protocol/libs/radiogatun.c \
	protocol/libs/sph_radiogatun.h \
	protocol/libs/ripemd.c \
	protocol/libs/sph_ripemd.h \
	protocol/libs/sha0.c \
	protocol/libs/sph_sha0.h \
	protocol/libs/sha1.c \
	protocol/libs/sph_sha1.h \
	protocol/libs/sha2big.c \
	protocol/libs/sha2.c \
	protocol/libs/sph_sha2.h \
	protocol/libs/sha3nist.c \
	protocol/libs/sph_sha3.h \
	protocol/libs/shabal.c \
	protocol/libs/sph_shabal.h \
	protocol/libs/shavite.c \
	protocol/libs/sph_shavite.h \
	protocol/libs/simd.c \
	protocol/libs/sph_simd.h \
	protocol/libs/speed.c \
	protocol/libs/skein.c \
	protocol/libs/sph_skein.h \
	protocol/libs/tiger.c \
	protocol/libs/sph_tiger.h \
	protocol/libs/sph_types.h \
	protocol/libs/whirlpool.c \
	protocol/libs/sph_whirlpool.h

# common: shared between dynamicd, and dynamic-qt and non-server tools
libdynamic_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
libdynamic_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  bip39.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  core_read.cpp \
  core_write.cpp \
  hash.cpp \
  hdchain.cpp \
  key.cpp \
  keystore.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  spork.cpp \
  $(DYNAMIC_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libdynamic_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
libdynamic_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_util_a_SOURCES = \
  support/pagelocker.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpcprotocol.cpp \
  support/cleanse.cpp \
  support/lockedpool.cpp \
  sync.cpp \
  uint256.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(DYNAMIC_CORE_H)

if GLIBC_BACK_COMPAT
libdynamic_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between dynamic-cli and dynamic-qt
libdynamic_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
libdynamic_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdynamic_cli_a_SOURCES = \
  rpcclient.cpp \
  $(DYNAMIC_CORE_H)

nodist_libdynamic_util_a_SOURCES = $(srcdir)/obj/build.h
#

# dynamicd binary #
dynamicd_SOURCES = dynamicd.cpp
dynamicd_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
dynamicd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
dynamicd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
dynamicd_SOURCES += dynamicd-res.rc
endif

dynamicd_LDADD = \
  $(LIBDYNAMIC_SERVER) \
  $(LIBDYNAMIC_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBDYNAMIC_UTIL) \
  $(LIBDYNAMIC_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBCRYPTOPP)

if ENABLE_ZMQ
dynamicd_LDADD += $(LIBDYNAMIC_ZMQ) $(ZMQ_LIBS)
endif

if ENABLE_WALLET
dynamicd_LDADD += libdynamic_wallet.a
endif

dynamicd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)

# dynamic-cli binary #
dynamic_cli_SOURCES = dynamic-cli.cpp
dynamic_cli_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES) $(EVENT_CFLAGS)
dynamic_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
dynamic_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
dynamic_cli_SOURCES += dynamic-cli-res.rc
endif

dynamic_cli_LDADD = \
  $(LIBDYNAMIC_CLI) \
  $(LIBUNIVALUE) \
  $(LIBDYNAMIC_UTIL)
dynamic_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

#############################
##
## Commented out for protocol
##
#############################

# dynamic-tx binary #
#dynamic_tx_SOURCES = dynamic-tx.cpp
#dynamic_tx_CPPFLAGS = $(AM_CPPFLAGS) $(DYNAMIC_INCLUDES)
#dynamic_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
#dynamic_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

#if TARGET_WINDOWS
#dynamic_tx_SOURCES += dynamic-tx-res.rc
#endif

#dynamic_tx_LDADD = \
#  $(LIBUNIVALUE) \
#  $(LIBDYNAMIC_COMMON) \
#  $(LIBDYNAMIC_UTIL) \
#  $(LIBDYNAMIC_CRYPTO) \
#  $(LIBSECP256K1) \
#  $(LIBCRYPTOPP)

#dynamic_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# dynamicconsensus library #
if BUILD_DYNAMIC_LIBS
include_HEADERS = script/dynamicconsensus.h
libdynamicconsensus_la_SOURCES = \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/dynamicconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libdynamicconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libdynamicconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libdynamicconsensus_la_LIBADD = $(LIBSECP256K1)
libdynamicconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_DYNAMIC_INTERNAL
libdynamicconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a
CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-$(MAKE) -C cryptopp clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config/dynamic-config.* config/stamp-h1

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
