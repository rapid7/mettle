require 'fileutils'
require 'bundler/gem_tasks'

task default: 'mettle:build'
task check: 'mettle:check'

namespace :mettle do
  desc 'Remove all build artifacts and tools'
  task :ultraclean => :clobber do
    FileUtils.rm_rf 'build/'
    FileUtils.rm Dir.glob 'musl-cross*.xz'
  end

  desc 'Make mettle for all architectures'
  task :build do
    each_arch do |tuple|
      puts "Building target #{tuple}"
      unless system "make TARGET=#{tuple}"
        $stderr.puts "Failed to build #{tuple}"
        exit false
      end
    end
  end

  desc 'Sanity check for mettle artifacts'
  task :check do
    success = true
    each_arch do |tuple|
      file = "build/#{tuple}/bin/mettle"

      if File.exists? "#{file}.exe"
        next
      end
      unless File.exists? file
        insane tuple, 'mettle executable does not exist'
        success = false
        next
      end
      unless File.size(file) < 1024 * 2048
        insane tuple, 'mettle executable looks too big'
        success = false
      end
      unless File.exists? "#{file}.bin"
        insane tuple, 'mettle.bin (memory image) does not exist'
        success = false
      end

      objdump = "build/tools/musl-cross/bin/#{tuple}-objdump"
      needed = `#{objdump} -p #{file} | grep NEEDED`.strip
      addr = `#{objdump} -p #{file} | grep LOAD | head -1`.strip.
        match(/.* vaddr (0x[0]*) .*/)[0]

      if needed != ""
        # We need external shared objects
        insane tuple, 'does not look static'
        success = false
      end

      if addr == nil
        # The first load section has a virtual address other than zero
        insane tuple, 'does not look PIE'
        success = false
      end
    end

    $stderr.puts 'All binaries look sane' if success

    exit success
  end
end

def each_arch(&block)
  File.readlines('ARCHES').each do |tuple|
    block.call tuple.strip
  end
end

def insane(tuple, why)
  $stderr.puts "Sanity check failed for #{tuple}: #{why}"
end

# Override tag_version in bundler-#.#.#/lib/bundler/gem_helper.rb to force signed tags
module Bundler
  class GemHelper
    def tag_version
      sh "git tag -m \"Version #{version}\" -s #{version_tag}"
      Bundler.ui.confirm "Tagged #{version_tag}."
      yield if block_given?
    rescue
      Bundler.ui.error "Untagging #{version_tag} due to error."
      sh_with_code "git tag -d #{version_tag}"
      raise
    end
  end
end
