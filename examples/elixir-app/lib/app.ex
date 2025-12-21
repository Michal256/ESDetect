defmodule ElixirApp do
  def main do
    loop()
  end

  defp loop do
    IO.puts "Hello World from Elixir!"
    
    # 1. Jason
    json = Jason.encode!(%{"hello" => "world"})
    IO.puts "JSON: #{json}"

    # 2. Decimal
    d = Decimal.new("1.23")
    IO.puts "Decimal: #{d}"

    # 3. UUID
    u = UUID.uuid4()
    IO.puts "UUID: #{u}"

    # 4. HTTPoison
    case HTTPoison.get("https://www.google.com") do
      {:ok, %HTTPoison.Response{status_code: 200}} ->
        IO.puts "HTTPoison: Google is up!"
      {:ok, %HTTPoison.Response{status_code: code}} ->
        IO.puts "HTTPoison: Google returned #{code}"
      {:error, %HTTPoison.Error{reason: reason}} ->
        IO.puts "HTTPoison Error: #{reason}"
    end

    Process.sleep(5000)
    loop()
  end
end
