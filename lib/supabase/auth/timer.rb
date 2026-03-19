# frozen_string_literal: true

module Supabase
  module Auth
    class Timer
      # @param interval [Float] delay in seconds before firing the callback
      # @param block [Proc] the callback to execute after the delay
      def initialize(interval, &block)
        @interval = interval
        @block = block
        @thread = nil
      end

      def start
        @thread = Thread.new do
          sleep @interval
          @block.call
        rescue StandardError
          # Swallow errors in timer thread (matches Python daemon thread behavior)
        end
        @thread
      end

      def cancel
        if @thread
          # Don't kill the current thread (e.g. when the callback triggers
          # a new timer via _save_session → _start_auto_refresh_token).
          # Python's threading.Timer.cancel() only prevents future execution;
          # it never terminates an already-running callback.
          @thread.kill unless @thread == Thread.current
          @thread = nil
        end
      end

      def alive?
        @thread&.alive? || false
      end
    end
  end
end
