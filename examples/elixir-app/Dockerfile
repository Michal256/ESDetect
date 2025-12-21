FROM elixir:1.16 AS build
WORKDIR /app
COPY mix.exs .
RUN mix local.hex --force && mix local.rebar --force
RUN mix deps.get
COPY lib ./lib
RUN mix compile

CMD ["mix", "run", "-e", "ElixirApp.main"]
