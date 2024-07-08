# frozen_string_literal: true

RSpec.describe MetasploitPayloads::Mettle do
  describe '::VERSION' do
    it 'has a version number' do
      expect(MetasploitPayloads::Mettle::VERSION).not_to be nil
    end
  end

  describe '::Error' do
    it 'has an error class' do
      expect(MetasploitPayloads::Mettle::Error.superclass).to be(StandardError)
    end

    it 'has an NotFoundError class' do
      expect(MetasploitPayloads::Mettle::NotFoundError.superclass).to be(MetasploitPayloads::Mettle::Error)
    end
  end

  subject { described_class.new('build-triple', { uri: 'mock-uri', uuid: 'mock-uuid', debug: false }) }

  describe '#short_opt' do
    [
      { opt: :background, expected: 'b' },
      { opt: :debug, expected: 'd' },
      { opt: :name, expected: 'n' },
      { opt: :log_file, expected: 'o' },
      { opt: :uri, expected: 'u' },
      { opt: :uuid, expected: 'U' },
      { opt: :session_guid, expected: 'G' }
    ].each do |test|
      context "when the opt is #{test[:opt]}" do
        it "returns the value #{test[:expected]}" do
          expect(subject.send(:short_opt, test[:opt])).to eq(test[:expected])
        end
      end
    end

    context 'when the opt is invalid' do
      it 'raises an error' do
        expect do
          subject.send(:short_opt, :invalid_opt)
        end.to raise_error MetasploitPayloads::Mettle::Error, 'unknown mettle option invalid_opt'
      end
    end
  end

  describe '.load_extension' do
    before(:each) do
      allow(described_class).to receive(:data_directory).and_return(File.join(Dir.pwd, 'build'))
    end

    context 'when the extension is found' do
      before(:each) do
        expected_path = 'mettle/build/build-tuple/bin/modname.bin'
        allow(::File).to receive(:readable?).and_call_original
        allow(::File).to receive(:readable?).with(/#{expected_path}$/).and_return(true)

        allow(::File).to receive(:binread).and_call_original
        allow(::File).to receive(:binread).with(/#{expected_path}$/).and_return('mock-extension')
      end

      it 'returns the extension' do
        expect(described_class.load_extension('build-tuple', 'modname', 'bin')).to eq 'mock-extension'
      end
    end

    context 'when the build tuple is wrong' do
      it 'raises an error' do
        expect do
          described_class.load_extension(
            'build-tuple',
            'modname',
            nil
          )
        end.to raise_error MetasploitPayloads::Mettle::NotFoundError, 'build-tuple/modname not found'
      end
    end

    context 'when the suffix is wrong' do
      it 'raises an error' do
        expect do
          described_class.load_extension(
            'build-tuple',
            'modname',
            'suffix'
          )
        end.to raise_error MetasploitPayloads::Mettle::NotFoundError, 'build-tuple/modname.suffix not found'
      end
    end

    context 'when the suffix contains only whitespace' do
      it 'raises an error' do
        expect do
          described_class.load_extension(
            'build-tuple',
            'modname',
            '           '
          )
        end.to raise_error MetasploitPayloads::Mettle::NotFoundError, 'build-tuple/modname not found'
      end
    end
  end
end
