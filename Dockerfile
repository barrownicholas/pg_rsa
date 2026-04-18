ARG PG_VERSION=17

FROM postgres:${PG_VERSION} AS deps
ARG PG_VERSION
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libssl-dev \
    postgresql-server-dev-${PG_VERSION} \
    && rm -rf /var/lib/apt/lists/*

FROM deps AS build

WORKDIR /pg_rsa
COPY dist/pg_rsa.c dist/
COPY Makefile .
COPY src/ src/

RUN make

FROM postgres:${PG_VERSION}

COPY --from=build /pg_rsa/pg_rsa.so /tmp/pg_rsa.so
COPY /dist/pg_rsa.control /tmp/pg_rsa.control
COPY /dist/sql/ /tmp/sql/

RUN mv /tmp/pg_rsa.so $(pg_config --pkglibdir)/pg_rsa.so && \
    mv /tmp/pg_rsa.control $(pg_config --sharedir)/extension/pg_rsa.control && \
    mv /tmp/sql/*.sql $(pg_config --sharedir)/extension/

ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_DB=postgres