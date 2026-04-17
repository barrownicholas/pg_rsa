MODULES = pg_rsa
EXTENSION = pg_rsa
DATA = sql/pg_rsa--1.0.sql

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)

PG_CFLAGS  += $(shell pkg-config --cflags openssl)
PG_LDFLAGS += $(shell pkg-config --libs openssl)

include $(PGXS)
