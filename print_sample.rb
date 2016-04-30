#!/usr/bin/env ruby

ERROR_MESSAGE = File.basename($PROGRAM_NAME) + " <sample_percentage> <input_file>"

if ARGV.size != 2
  puts ERROR_MESSAGE
  exit
end

percentage = ARGV[0]
file = ARGV[1]

if not percentage =~ /^[0-9]+$/
  puts "Sample percentage is not valid!"
  puts ERROR_MESSAGE
  exit
end

percentage = percentage.to_i

if not File.exists?(file)
  puts "File does not exist!"
  puts ERROR_MESSAGE
  exit
end


lines = IO.readlines(file)
sample = ((percentage.to_f / 100.0) * lines.size.to_f).to_i
numbers = sample.times.map { Random.rand(lines.size) }
numbers.each do |n|
  puts lines[n]
end
