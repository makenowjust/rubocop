# frozen_string_literal: true

module RuboCop
  module Cop
    module Security
      # Do not use non-linear features in regexp due to the risk of ReDoS.
      #
      # ReDoS (Regular Expression Denial of Service) is a vulneability caused
      # by catastrophic backtracking on Regexp matching. See
      # https://en.wikipedia.org/wiki/ReDoS.
      #
      # Since Ruby 3.2, the improvement to suppress catastrophic backtracking
      # have been introduced. Unfortunately, this improvement does not catch
      # all regexps, so some regexps are still ReDoS vulnerable. For example,
      # back-references and sub-expression calls are not supported. This cop
      # detects usages of such non-linear features in regexps.
      #
      # @safety
      #   This cop uses `Regexp.linear_time?` to detect non-linear regexp.
      #   Therefore, results may be changed depending on the version of Ruby in
      #   which Rubocop is run, and safety of results is guaranteed only for that
      #   version of Ruby.
      #
      # @example
      #   # bad
      #   /("|').+\1/
      #   /\A(?<a>|.|(?:(?<b>.)\g<a>\k<b+0>))\z/
      #
      #   # good
      #   foo = /.+/
      #   /("|')#{foo}\1/ # a regexp having interpolations is not checked
      #
      class NonLinearRegexp < Base
        extend TargetRubyVersion

        MSG = 'Do not use non-linear features in regexp due to the risk of ReDoS.'

        minimum_target_ruby_version 3.2

        def on_regexp(node)
          return if node.interpolation?

          regexp = node.to_regexp
          return if Regexp.linear_time?(regexp)

          add_offense(node)
        end
      end
    end
  end
end
