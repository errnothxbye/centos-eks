require 'nokogiri'
require 'open-uri'
require 'fileutils'
require 'securerandom'
require 'logger'

# Link to the calculus/table doc
aws_eni_doc = Nokogiri::HTML(open('https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI'))
# Temp file
tmp_eni_file = "/tmp/#{SecureRandom.uuid}.tmp"
# Default location for the eni file
eni_file = "/etc/kubernetes/misc/eni-max-pods.txt"
# Init logger
@LOGGER = Logger.new(STDOUT)

# lok'tar ogar
def pod_calc(eni_file, tmp_eni_file, aws_eni_doc)
  begin
    # Search for the table with numbers on the aws_eni_doc page
    aws_eni_doc.css('table:not([summary=Breadcrumbs])').search('tr').each do |row|
      cells = row.css('td').map { |cell| cell.text.strip }
      # Append lines to a tmp file
      File.open(tmp_eni_file, 'a') do |line|
        line.write("#{cells[0]} #{cells[1].to_i * (cells[2].to_i - 1) + 2}\n") unless cells.empty?
      end
    end
    # cp tmp file to the eni_file location
    FileUtils.cp(tmp_eni_file, eni_file)
    # rm tmp file
    FileUtils.rm_rf(tmp_eni_file)
    @LOGGER.info("Generated #{eni_file}") and true
  rescue IOError, Errno::ENOENT, Errno::EACCES, Errno::ENOTDIR
    @LOGGER.error($!.message) and false
  end
end

# Log non-specific failure if the method fails.
@LOGGER.error("Failed to create #{eni_file}") unless pod_calc(eni_file, tmp_eni_file, aws_eni_doc)
