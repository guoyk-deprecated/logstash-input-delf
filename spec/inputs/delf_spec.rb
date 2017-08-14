# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/delf"
require_relative "../support/helpers"
require "gelf"
require "flores/random"

describe LogStash::Inputs::Delf do
  context "when interrupting the plugin" do
    let(:port) { Flores::Random.integer(1024..65535) }
    let(:host) { "127.0.0.1" }
    let(:chunksize) { 1420 }
    let(:producer) { InfiniteDelfProducer.new(host, port, chunksize) }
    let(:config) {  { "host" => host, "port" => port } }

    before { producer.run }
    after { producer.stop }


    it_behaves_like "an interruptible input plugin"
  end

  it "reads chunked gelf messages " do
    port = 12209
    host = "127.0.0.1"
    chunksize = 1420
    gelfclient = GELF::Notifier.new(host, port, chunksize)

    conf = <<-CONFIG
      input {
        delf {
          port => "#{port}"
          host => "#{host}"
        }
      }
    CONFIG

    large_random = 2000.times.map{32 + rand(126 - 32)}.join("")

    messages = [
      "hello",
      "world",
      large_random,
      "we survived delf!"
    ]

    events = input(conf) do |pipeline, queue|
      # send a first message until plugin is up and receives it
      while queue.size <= 0
        gelfclient.notify!("short_message" => "prime")
        sleep(0.1)
      end
      gelfclient.notify!("short_message" => "start")

      e = queue.pop
      while (e.get("message") != "start")
        e = queue.pop
      end

      messages.each do |m|
  	    gelfclient.notify!("short_message" => m)
      end

      messages.map{queue.pop}
    end

    events.each_with_index do |e, i|
      insist { e.get("message") } == messages[i]
      insist { e.get("host") } == Socket.gethostname
    end
  end

  it "handles multi-line messages " do
    port = 12209
    host = "127.0.0.1"
    chunksize = 1420
    gelfclient = GELF::Notifier.new(host, port, chunksize)

    conf = <<-CONFIG
      input {
        delf {
          port => "#{port}"
          host => "#{host}"
        }
      }
    CONFIG

    messages = [{
      "_container_id" => "dummy1",
      "short_message" => "single1"
    },{
      "_container_id" => "dummy2",
      "short_message" => "single2"
    },{
      "_container_id" => "dummy1",
      "short_message" => "multi1\\"
    },{
      "_container_id" => "dummy2",
      "short_message" => "multi2\\"
    },{
      "_container_id" => "dummy1",
      "short_message" => "multi3\\"
    },{
      "_container_id" => "dummy2",
      "short_message" => "multi4\\"
    },{
      "_container_id" => "dummy2",
      "short_message" => "multi5" # dummy2 multi ended first
    },{
      "_container_id" => "dummy1",
      "short_message" => "multi6"
    },{
      "_container_id" => "dummy2",
      "short_message" => "single3"
    },{
      "_container_id" => "dummy1",
      "short_message" => "single4"
    }]

    events = input(conf) do |pipeline, queue|
      # send a first message until plugin is up and receives it
      while queue.size <= 0
        gelfclient.notify!("short_message" => "prime")
        sleep(0.1)
      end
      gelfclient.notify!("short_message" => "start")

      e = queue.pop
      while (e.get("message") != "start")
        e = queue.pop
      end

      messages.each do |m|
        gelfclient.notify!(m)
      end

      results = []

      6.times do
        results << queue.pop
      end

      results
    end

    insist { events.count } == 6

    insist { events[0].get("container_id") } == "dummy1"
    insist { events[0].get("message") } == "single1"
    insist { events[1].get("container_id") } == "dummy2"
    insist { events[1].get("message") } == "single2"
    insist { events[2].get("container_id") } == "dummy2"
    insist { events[2].get("message") } == "multi2\r\nmulti4\r\nmulti5"
    insist { events[3].get("container_id") } == "dummy1"
    insist { events[3].get("message") } == "multi1\r\nmulti3\r\nmulti6"
    insist { events[4].get("container_id") } == "dummy2"
    insist { events[4].get("message") } == "single3"
    insist { events[5].get("container_id") } == "dummy1"
    insist { events[5].get("message") } == "single4"
  end

  context "timestamp coercion" do
    # these test private methods, this is advisable for now until we roll out this coercion in the Timestamp class
    # and remove this

    context "integer numeric values" do
      it "should coerce" do
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800).to_iso8601).to eq("2000-01-01T05:00:00.000Z")
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800).usec).to eq(0)
      end
    end

    context "float numeric values" do
      # using explicit and certainly useless to_f here just to leave no doubt about the numeric type involved

      it "should coerce and preserve millisec precision in iso8601" do
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.1.to_f).to_iso8601).to eq("2000-01-01T05:00:00.100Z")
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.12.to_f).to_iso8601).to eq("2000-01-01T05:00:00.120Z")
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.123.to_f).to_iso8601).to eq("2000-01-01T05:00:00.123Z")
      end

      it "should coerce and preserve usec precision" do
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.1.to_f).usec).to eq(100000)
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.12.to_f).usec).to eq(120000)
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.123.to_f).usec).to eq(123000)

        # since Java Timestamp in 2.3+ relies on JodaTime which supports only millisec precision
        # the usec method will only be precise up to millisec.
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.1234.to_f).usec).to be_within(1000).of(123400)
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.12345.to_f).usec).to be_within(1000).of(123450)
        expect(LogStash::Inputs::Delf.coerce_timestamp(946702800.123456.to_f).usec).to be_within(1000).of(123456)
      end
    end

    context "BigDecimal numeric values" do
      it "should coerce and preserve millisec precision in iso8601" do
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.1")).to_iso8601).to eq("2000-01-01T05:00:00.100Z")
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.12")).to_iso8601).to eq("2000-01-01T05:00:00.120Z")
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.123")).to_iso8601).to eq("2000-01-01T05:00:00.123Z")
      end

      it "should coerce and preserve usec precision" do
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.1")).usec).to eq(100000)
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.12")).usec).to eq(120000)
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.123")).usec).to eq(123000)

        # since Java Timestamp in 2.3+ relies on JodaTime which supports only millisec precision
        # the usec method will only be precise up to millisec.
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.1234")).usec).to be_within(1000).of(123400)
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.12345")).usec).to be_within(1000).of(123450)
        expect(LogStash::Inputs::Delf.coerce_timestamp(BigDecimal.new("946702800.123456")).usec).to be_within(1000).of(123456)
      end
    end
  end

  context "json timestamp coercion" do
    # these test private methods, this is advisable for now until we roll out this coercion in the Timestamp class
    # and remove this

    it "should coerce integer numeric json timestamp input" do
      event = LogStash::Inputs::Delf.new_event("{\"timestamp\":946702800}", "dummy")
      expect(event.timestamp.to_iso8601).to eq("2000-01-01T05:00:00.000Z")
    end

    it "should coerce float numeric value and preserve milliseconds precision in iso8601" do
      event = LogStash::Inputs::Delf.new_event("{\"timestamp\":946702800.123}", "dummy")
      expect(event.timestamp.to_iso8601).to eq("2000-01-01T05:00:00.123Z")
    end

    it "should coerce float numeric value and preserve usec precision" do
      # since Java Timestamp in 2.3+ relies on JodaTime which supports only millisec precision
      # the usec method will only be precise up to millisec.

      event = LogStash::Inputs::Delf.new_event("{\"timestamp\":946702800.123456}", "dummy")
      expect(event.timestamp.usec).to be_within(1000).of(123456)
    end
  end

  context "when an invalid JSON is fed to the listener" do
    subject { LogStash::Inputs::Delf.new_event(message, "host") }
    let(:message) { "Invalid JSON message" }

    if LogStash::Event.respond_to?(:from_json)
      context "default :from_json parser output" do
        it { should be_a(LogStash::Event) }

        it "falls back to plain-text" do
          expect(subject.get("message")).to eq(message)
        end

        it "tags message with _jsonparsefailure" do
          expect(subject.get("tags")).to include("_jsonparsefailure")
        end

        it "tags message with _fromjsonparser" do
          expect(subject.get("tags")).to include("_fromjsonparser")
        end
      end
    else
      context "legacy JSON parser output" do
        it { should be_a(LogStash::Event) }

        it "falls back to plain-text" do
          expect(subject.get("message")).to eq(message)
        end

        it "tags message with _jsonparsefailure" do
          expect(subject.get("tags")).to include("_jsonparsefailure")
        end

        it "tags message with _legacyjsonparser" do
          expect(subject.get("tags")).to include("_legacyjsonparser")
        end
      end
    end
  end
end
