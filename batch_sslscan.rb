#!/usr/bin/env ruby

binary='sslscan'

ERROR_MESSAGE = File.basename($PROGRAM_NAME) + " <file_of_ip_addresses> <port>"

if ARGV.size != 2
  puts ERROR_MESSAGE
  exit
end

input_file = ARGV[0]
port = ARGV[1]

if not File.exists?(input_file)
  puts "'#{input_file}' does not exist!"
  puts ERROR_MESSAGE
  exit
end

servers = IO.readlines(input_file)

servers.each do |server|
#  print "Connecting to #{server.chomp}..."
#  system "#{binary} #{server.chomp}:#{port} > #{server.chomp.gsub(/\//, '').gsub(/:/,'_')}.txt"
#  puts "done."
  system "#{binary} #{server.chomp}:#{port}"
end
