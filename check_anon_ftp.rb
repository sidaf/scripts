#!/usr/bin/env ruby

require 'net/ftp'
require 'stringio'
require 'securerandom'

ERROR_MESSAGE = File.basename($PROGRAM_NAME) + " <file_of_ftp_servers>"

if ARGV.size != 1
  puts ERROR_MESSAGE
  exit
end

file = ARGV[0]

if not File.exists?(file)
  puts "#{file} does not exist!"
  puts ERROR_MESSAGE
  exit
end

modes = [:active, :passive]

servers = IO.readlines(file)

servers.each do |server|
  modes.each do |mode|
    print "[+] Connecting to #{server.chomp} [#{mode} mode]..."
    begin
      address, port = server.split(':') 
      ftp = Net::FTP.new
      if mode == :passive
	ftp.passive = true
      end
      if port == nil
	ftp.connect(address)
      else
	ftp.connect(address, port)
      end
      puts "done"
      print "[+]   Authenticating using anonymous credentials..."
      ftp.login('anonymous', 'test@test.me')
      puts "done"
      print "[+]     Listing files in root directory..."
      files = ftp.list
      if files.empty?
	puts "empty"
      else
	puts ""
      end
      files.each do |file|
	puts " #{file}"
      end
      # Check if file upload is possible
      file = StringIO.new("Test - please delete me if found")
      filename = "#{SecureRandom.hex}.txt"
      print "[+]       Uploading file #{filename}..."
      begin  
	ftp.storlines("STOR #{filename}", file)
	puts "allowed"
	print "[-]     Deleting file #{filename}..."
	ftp.delete(filename)
	puts "done"
      rescue Net::FTPPermError
	puts "access denied"
      end
    rescue SocketError
      puts "host or service not known"
    rescue Net::FTPPermError
      puts "access denied"
    rescue Errno::ETIMEDOUT
      puts "connection timed out"
    rescue Net::FTPReplyError
      puts "access denied"
    rescue Net::FTPProtoError
      puts "error"
    end
  end
end
