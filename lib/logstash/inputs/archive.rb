# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "socket" # for Socket.gethostname
require "fileutils"
require "shellwords"

# Read events from log files within an archive.
#
# This plugin supports many different types of archives. To see
# which archive formats are supported, please refer to the
# documentation for the `path` option (below). This plugin can
# handle very large archive files with ease.
#
# This plugin also supports watching directories (i.e., periodically
# evaluating a glob and checking whether any new files have appeared).
#
# By default, each event is assumed to be one line. If you would like
# to join multiple log lines into one event, you'll want to use the
# multiline codec.
class LogStash::Inputs::Archive < LogStash::Inputs::Base
  config_name "archive"
  milestone 1

  default :codec, "line"

  # The path(s) to the file(s) to use as an input.
  # You can use globs here, such as `/var/log/*.log`
  # Paths must be absolute and cannot be relative.
  #
  # You may also configure multiple paths. See an example
  # on the [Logstash configuration page](configuration#array).
  #
  # Currently, this plugin supports the following archive types:
  # gzip (.gz), tar-bzip2 (.tar.bz2), bzip2 (.bz2), 7zip (.7z),
  # and rar (.rar).
  #
  # Support for tar.bz and zip is coming soon.
  #
  # Please note that you may need to install additional packages
  # in order to process certain types of archives (anything other
  # than *.gz).
  #
  # Please note that the archive will be decompressed using a
  # decompression algorithm selected from the file extension. For
  # example, the file 'MyArchive.rar' would be decompressed using
  # the `unrar` tool. If this approach fails, the decompression
  # algorithm will fallback to using magic numbers.
  config :path, :validate => :array, :required => true

  # Exclusions (matched against the filename, not full path). Globs
  # are valid here, too. For example, if you have
  #
  #     path => "/var/log/*.gz"
  #
  # You might want to exclude 7zipped files:
  #
  #     exclude => "*.7z"
  config :exclude, :validate => :array

  # How often we expand globs to discover new files to watch.
  config :discover_interval, :validate => :number, :default => 15

  private
  def check_dependency(program, path)
    case program
    when 'tar_bzip2'
      if system('/usr/bin/which tar 2>&1 > /dev/null')
        return true
      else
        @logger.warn("You need to have tar (package tar) installed to process #{path}. Skipping...")
        return false
      end
    when 'bzip2'
      if system('/usr/bin/which bzcat 2>&1 > /dev/null')
          return true
      else
        @logger.warn("You need to have bzcat (package bzip2) installed to process #{path}. Skipping...")
        return false
      end
    when '7zip'
      if system('/usr/bin/which 7za 2>&1 > /dev/null')
        return true
      else
        @logger.warn("You need to have 7za (package p7zip) installed to process #{path}. Skipping...")
        return false
      end
    when 'rar'
      if system('/usr/bin/which unrar 2>&1 > /dev/null')
        return true
      else
        @logger.warn("You need to have unrar (package unrar) installed to process #{path}. Skipping...")
        return false
      end
    else
      return true
    end
  end

  public
  def register
    require 'set'
    require 'zlib'

    @logger.info("Registering archive input", :path => @path)
    @logger.info("Please note that additional packages may be required to process certain archive formats.")

    @exclude = [] unless defined? @exclude

    @path.each do |path|
      if Pathname.new(path).relative?
        raise ArgumentError.new("File paths must be absolute, relative path specified: #{path}")
      end
    end
  end # def register

  public
  def run(queue)
    processed_files = Set.new

    has_globs = false

    loop do
      @path.each do |globpath|
        has_globs ||= !!(globpath =~ /[*?\[\]^{}]/)

        filenames = Dir.glob(globpath)

        for filename in filenames
          next if processed_files.member?(filename)
          next if @exclude.any? { |rule| File.fnmatch?(rule, File.basename(filename)) }

          begin
            process(queue, filename)
          rescue
            @logger.error("A critical error occured when processing #{filename}. Skipping...")
          end

          processed_files << filename
        end
      end

      unless has_globs
        # if no globs were given, then there is nothing else we can do
        break
      end

      sleep(@discover_interval)
    end

    finished
  end # def run

  private
  def process(queue, path)
    hostname = Socket.gethostname

    if File.fnmatch?('*.gz', path)
      process_gzip(queue, path, hostname)
    elsif File.fnmatch?('*.tar.bz2', path)
      process_tar_bzip2(queue, path, hostname) if check_dependency('tar_bzip2', path)
    elsif File.fnmatch?('*.bz2', path)
      process_bzip2(queue, path, hostname) if check_dependency('bzip2', path)
    elsif File.fnmatch?('*.7z', path)
      process_7zip(queue, path, hostname) if check_dependency('7zip', path)
    elsif File.fnmatch?('*.rar', path)
      process_rar(queue, path, hostname) if check_dependency('rar', path)
    else
      # try to detect compression type via magic numbers
      begin
        magic_number = File.open(path, 'rb').read(2)
      rescue
        @logger.warn("Could not identify compression of #{path}. Ignoring...")
      end

      case magic_number
      when "\x1f\x8b"
        process_gzip(queue, path, hostname)
      when "BZ" # it could be either .tar.bz2 or .bz2; let's assume .bz2
        process_bzip2(queue, path, hostname) if check_dependency('bzip2', path)
      when "7z"
        process_7zip(queue, path, hostname) if check_dependency('7zip', path)
      when "Ra"
        process_rar(queue, path, hostname) if check_dependency('rar', path)
      else
        @logger.warn("Unsupported archive type: #{path}. Ignoring...")
      end
    end
  end # def process

  private
  def process_gzip(queue, path, hostname)
    begin
      gz = Zlib::GzipReader.open(path)
    rescue Zlib::GzipFile::Error
      @logger.warn("An error occured when decompressing #{path}. Ignoring...")
      return
    rescue
      @logger.warn("An error occured when processing #{path}. Ignoring...")
      return
    end

    gz.each_line do |line|
      @logger.debug? && @logger.debug("Received line", :path => path, :text => line)
      @codec.decode(line) do |event|
        decorate(event)
        event["host"] ||= hostname
        event["path"] ||= path
        queue << event
      end
    end
  end # def process_gzip

  private
  def process_tar_bzip2(queue, path, hostname)
    tmp_dir = "/tmp/ls#{Time.now.to_i}"

    FileUtils.mkdir(tmp_dir)
    system("/usr/bin/env tar -xjf #{path.shellescape} -C #{tmp_dir} 2>&1 > /dev/null")

    if $? != 0
      @logger.warn("An error occured when extracting #{path}. Ignoring...")
      FileUtils.rm_rf(tmp_dir)
      return
    end

    Dir.glob("#{tmp_dir}/**/*.*").each do |ext_filename|
      ext_basename = File.basename(ext_filename)

      begin
        file = File.open(ext_filename)
        file.each_line do |line|
          @logger.debug? && @logger.debug("Received line", :path => path, :text => line)
          @codec.decode(line) do |event|
            decorate(event)
            event["host"] ||= hostname
            event["path"] ||= path
            queue << event
          end
        end
      rescue
        @logger.warn("An error occured when processing #{path}:#{ext_basename}. Ignoring...")
      end
    end

    FileUtils.rm_rf(tmp_dir)
  end # def process_tar_bzip2

  private
  def process_bzip2(queue, path, hostname)
    tmp_file = "/tmp/ls#{Time.now.to_i}"

    system("/usr/bin/env bzcat #{path.shellescape} > #{tmp_file}")

    if $? != 0
      @logger.warn("An error occured when extracting #{path}. Ignoring...")
      return
    end

    begin
      file = File.open(tmp_file)
      file.each_line do |line|
        @logger.debug? && @logger.debug("Received line", :path => path, :text => line)
        @codec.decode(line) do |event|
          decorate(event)
          event["host"] ||= hostname
          event["path"] ||= path
          queue << event
        end
      end
    rescue
      @logger.warn("An error occured when processing #{path}. Ignoring...")
    end

    FileUtils.rm(tmp_file)
  end # def process_bzip2

  private
  def process_7zip(queue, path, hostname)
    tmp_dir = "/tmp/ls#{Time.now.to_i}"

    FileUtils.mkdir(tmp_dir)
    system("/usr/bin/env 7za e -o#{tmp_dir} -y #{path.shellescape} 2>&1 > /dev/null")

    if $? != 0
      @logger.warn("An error occured when extracting #{path}. Ignoring...")
      FileUtils.rm_rf(tmp_dir)
      return
    end

    Dir.glob("#{tmp_dir}/**/*.*").each do |ext_filename|
      ext_basename = File.basename(ext_filename)

      begin
        file = File.open(ext_filename)
        file.each_line do |line|
          @logger.debug? && @logger.debug("Received line", :path => path, :text => line)
          @codec.decode(line) do |event|
            decorate(event)
            event["host"] ||= hostname
            event["path"] ||= path
            queue << event
          end
        end
      rescue
        @logger.warn("An error occured when processing #{path}:#{ext_basename}. Ignoring...")
      end
    end

    FileUtils.rm_rf(tmp_dir)
  end # def process_7zip

  private
  def process_rar(queue, path, hostname)
    tmp_dir = "/tmp/ls#{Time.now.to_i}"

    FileUtils.mkdir(tmp_dir)
    system("/usr/bin/env unrar e -y #{path.shellescape} #{tmp_dir}/ 2>&1 > /dev/null")

    if $? != 0
      @logger.warn("An error occured when extracting #{path}. Ignoring...")
      FileUtils.rm_rf(tmp_dir)
      return
    end

    Dir.glob("#{tmp_dir}/**/*.*").each do |ext_filename|
      ext_basename = File.basename(ext_filename)

      begin
        file = File.open(ext_filename)
        file.each_line do |line|
          @logger.debug? && @logger.debug("Received line", :path => path, :text => line)
          @codec.decode(line) do |event|
            decorate(event)
            event["host"] ||= hostname
            event["path"] ||= path
            queue << event
          end
        end
      rescue
        @logger.warn("An error occured when processing #{path}:#{ext_basename}. Ignoring...")
      end
    end

    FileUtils.rm_rf(tmp_dir)
  end # def process_rar
end # class LogStash::Inputs::File
