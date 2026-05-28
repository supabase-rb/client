# frozen_string_literal: true

RSpec.describe Supabase::Auth do
  it "has a version number" do
    expect(Supabase::Auth::VERSION).to match(/\A\d+\.\d+\.\d+\z/)
  end
end
