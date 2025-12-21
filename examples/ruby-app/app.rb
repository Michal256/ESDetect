require 'sinatra'
require 'nokogiri'
require 'redis'
require 'aws-sdk-s3'

# Loop indefinitely
loop do
  # 1. Nokogiri
  doc = Nokogiri::HTML('<h1>Hello World from Ruby!</h1>')
  header = doc.at_css('h1').content
  puts header

  # 2. AWS SDK (Just instantiating, not connecting)
  s3 = Aws::S3::Resource.new(region: 'us-west-2', stub_responses: true)
  bucket_name = "my-bucket-#{Time.now.to_i}"
  
  # 3. Redis (Just instantiating)
  redis = Redis.new(url: "redis://localhost:6379")
  
  sleep 5
end
