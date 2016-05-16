require 'fileutils'
require 'bundler/gem_tasks'

task default: 'mettle:build'

namespace :mettle do
  desc 'Remove all build artifacts and tools'
  task :ultraclean => :clobber do
    FileUtils.rm_rf 'build/'
    FileUtils.rm Dir.glob 'musl-cross*.xz'
  end

  desc 'Make mettle for all architectures'
  task :build do
    system('./make-all')
  end
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
