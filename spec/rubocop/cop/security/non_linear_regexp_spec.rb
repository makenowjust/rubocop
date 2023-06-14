# frozen_string_literal: true

RSpec.describe RuboCop::Cop::Security::NonLinearRegexp, :config do
  context 'Ruby >= 3.2', :ruby32 do
    it 'registers an offense for a regexp literal using non-linear features' do
      expect_offense(<<~'RUBY')
        /('|").+\1/
        ^^^^^^^^^^^ Do not use non-linear features in regexp due to the risk of ReDoS.
      RUBY
    end

    it 'accepts a regexp literal whchi does not use non-linear features' do
      expect_no_offenses('/foo|bar/')
    end
  end
end
