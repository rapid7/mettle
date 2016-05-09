# -*- coding:binary -*-

unless defined? MetasploitPayloads::Mettle::VERSION
  require 'metasploit-payloads/mettle/version'
end

#
# This module dispenses Mettle payload binary files
#
module MetasploitPayloads
  module Mettle
    def self.readable_path(gem_path, msf_path)
      # Try the MSF path first to see if the file exists, allowing the MSF data
      # folder to override what is in the gem. This is very helpful for
      # testing/development without having to move the binaries to the gem folder
      # each time. We only do this is MSF is installed.
      if ::File.readable? msf_path
        warn_local_path(msf_path) if ::File.readable? gem_path
        msf_path
      elsif ::File.readable? gem_path
        gem_path
      end
    end

    #
    # Get the contents of any file packaged in this gem by local path and name.
    #
    def self.read(triple, file)
      file_path = path("cross-#{triple}", 'bin', file)
      if file_path.nil?
        full_path = ::File.join([triple, file])
        fail RuntimeError, "#{full_path} not found", caller
      end

      ::File.binread(file_path)
    end

    private

    #
    # Get the full path to any file packaged in this gem by local path and name.
    #
    def self.path(*path_parts)
      gem_path = expand(data_directory, ::File.join(path_parts))
	  msf_path = 'thisisnotthefileyouarelookingfor'
      if metasploit_installed?
        msf_path = expand(Msf::Config.data_directory, 'mettle', ::File.join(path_parts))
      end
      readable_path(gem_path, msf_path)
    end

    #
    # Full path to the local gem folder containing the base data
    #
    def self.data_directory
      ::File.realpath(::File.join(::File.dirname(__FILE__), '..', '..', 'build'))
    end

    #
    # Determine if MSF has been installed and is being used.
    #
    def self.metasploit_installed?
      defined? Msf::Config
    end

    #
    # Expand the given root path and file name into a full file location.
    #
    def self.expand(root_dir, file_name)
      ::File.expand_path(::File.join(root_dir, file_name))
    end

    @local_paths = []

    def self.warn_local_path(path)
      unless @local_paths.include?(path)
        STDERR.puts("WARNING: Local file #{path} is being used")
        if @local_paths.empty?
          STDERR.puts('WARNING: Local files may be incompatible Metasploit framework')
        end
        @local_paths << path
      end
    end
  end
end
