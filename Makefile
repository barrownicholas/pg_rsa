MODULE_big = pg_rsa
OBJS = dist/pg_rsa.o
DATA = dist/pg_rsa--1.0.sql
PG_CONFIG = pg_config
SHLIB_LINK = -lssl -lcrypto
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)