# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "socket" # for Socket.gethostname
require "fileutils"
require "shellwords"

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
  # Currently, gzip (.gz) and bzip2 (.bz2, NOT tar.bz2) archives
  # are supported.
  # Support for 7zip, rar, and zip is coming soon.
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

  public
  def register
    require 'set'
    require 'zlib'

    @logger.info("Registering archive input", :path => @path)

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

    loop do
      @path.each do |globpath|
        filenames = Dir.glob(globpath)

        for filename in filenames
          next if processed_files.member?(filename)
          next if @exclude.any? { |rule| File.fnmatch?(rule, File.basename(filename)) }

          process(queue, filename)
          processed_files << filename
        end
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
    elsif File.fnmatch?('*.bz2', path)
      process_bzip2(queue, path, hostname)
    else
      # try to detect compression type via magic numbers
      begin
        magic_number = File.open(path, 'rb').read(2)
        case magic_number
        when "\x1f\x8b"
          process_gzip(queue, path, hostname)
        when "BZ"
          process_bzip2(queue, path, hostname)
        else
          @logger.warn("Unsupported archive type: #{path}. Ignoring...")
        end
      rescue
        @logger.warn("Could not identify compression of #{path}. Ignoring...")
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
  def process_bzip2(queue, path, hostname)
    basename = File.basename(path)
    tmp_file = "/tmp/#{Time.now.to_i}"

    system("/bin/bzcat #{path.shellescape} > #{tmp_file}")

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
end # class LogStash::Inputs::File
