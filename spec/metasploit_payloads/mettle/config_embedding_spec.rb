# frozen_string_literal: true

# Regression coverage for the binary-safe embedding of the mettle config block
# and command-line argument slots.
#
# Both slots are filled with `String#sub`. When `sub` is given a *string*
# replacement it interprets backslash sequences (\0-\9, \\, \k<>, \&, ...).
# The config block is an (effectively random / XOR-encoded) binary blob, so it
# routinely contains a 0x5c ("\") byte followed by a digit. With the string
# form those sequences are expanded/dropped, which changes the length of the
# produced binary, shifts the trailing LC_CODE_SIGNATURE SuperBlob and breaks
# Mach-O signing downstream. The block form of `sub` does not interpret the
# replacement, keeping the bytes verbatim.
#
# These examples are RED against `bin.sub(pattern, replacement)` and GREEN
# against `bin.sub(pattern) { replacement }`.
RSpec.describe MetasploitPayloads::Mettle do
  subject { described_class.new('build-triple', {}) }

  # A selection of payloads that all embed cleanly with the block form but that
  # a string replacement would mangle (or, for the control cases, would not).
  binary_payloads = [
    { name: 'plain ascii bytes',                bytes: ('A'.b * 128) },
    { name: 'a literal \0 backreference',       bytes: ('A'.b * 16) + "\x5c\x30".b + ('A'.b * 16) },
    { name: 'a literal \1 backreference',       bytes: ('A'.b * 16) + "\x5c\x31".b + ('A'.b * 16) },
    { name: 'a literal \& whole-match ref',     bytes: ('A'.b * 16) + "\x5c\x26".b + ('A'.b * 16) },
    { name: 'a literal double backslash',       bytes: ('A'.b * 16) + "\x5c\x5c".b + ('A'.b * 16) },
    { name: 'a trailing null byte',             bytes: ('A'.b * 32) + "\x00".b },
    { name: 'every possible byte value',        bytes: (0..255).to_a.pack('C*') }
  ]

  describe '#add_config_block' do
    let(:sig) { described_class::CONFIG_BLOCK_SIG }
    let(:max) { described_class::CONFIG_BLOCK_MAX }
    let(:prefix) { 'MACHO-HEADER'.b }
    let(:suffix) { 'TRAILING-SIGNATURE'.b }
    let(:reserved_slot) { sig.b + ("\x00".b * (max - sig.length)) }
    let(:binary) { prefix + reserved_slot + suffix }

    binary_payloads.each do |test|
      context "when the config block contains #{test[:name]}" do
        let(:config_bytes) { test[:bytes] }
        let(:result) { subject.send(:add_config_block, binary.dup, config_bytes) }

        it 'preserves the overall binary size' do
          expect(result.length).to eq(binary.length)
        end

        it 'writes the 4-byte big-endian length prefix' do
          expect(result[prefix.length, 4]).to eq([config_bytes.length].pack('N'))
        end

        it 'writes the config bytes verbatim into the reserved slot' do
          expect(result[prefix.length + 4, config_bytes.length]).to eq(config_bytes)
        end

        it 'leaves the surrounding bytes untouched' do
          expect(result).to start_with(prefix)
          expect(result).to end_with(suffix)
        end
      end
    end

    context 'when the config block is larger than the reserved slot' do
      it 'raises an error' do
        expect do
          subject.send(:add_config_block, binary.dup, 'A'.b * (max - 3))
        end.to raise_error(described_class::Error, 'mettle config block too large')
      end
    end
  end

  describe '#add_args' do
    let(:sig) { described_class::CMDLINE_SIG }
    let(:max) { described_class::CMDLINE_MAX }
    let(:prefix) { 'MACHO-HEADER'.b }
    let(:suffix) { 'TRAILING-SIGNATURE'.b }
    let(:reserved_slot) { sig.b + (' '.b * (max - sig.length)) }
    let(:binary) { prefix + reserved_slot + suffix }

    cmdline_max = MetasploitPayloads::Mettle::CMDLINE_MAX

    binary_payloads.each do |test|
      # add_args only rewrites the slot when params[8] is not a null byte, so
      # build a params buffer of the required length whose 9th byte is set.
      params = ('mettle '.b + test[:bytes])[0, cmdline_max]
      params += "\x00".b * (cmdline_max - params.length)

      next if params[8] == "\x00".b

      context "when the argument buffer contains #{test[:name]}" do
        let(:result) { subject.send(:add_args, binary.dup, params) }

        it 'preserves the overall binary size' do
          expect(result.length).to eq(binary.length)
        end

        it 'writes the params verbatim into the reserved slot' do
          expect(result[prefix.length, max]).to eq(params)
        end

        it 'leaves the surrounding bytes untouched' do
          expect(result).to start_with(prefix)
          expect(result).to end_with(suffix)
        end
      end
    end
  end
end
