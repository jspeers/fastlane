require_relative 'globals'
require_relative 'tunes/tunes_client'
require 'google/apis/gmail_v1'
require 'googleauth'
require 'googleauth/stores/file_token_store'
require 'fileutils'
require 'date'



module Spaceship
  class Client
    OOB_URI = 'urn:ietf:wg:oauth:2.0:oob'.freeze
    APPLICATION_NAME = 'Gmail API Ruby Quickstart'.freeze
    CREDENTIALS_PATH = 'credentials.json'.freeze
# The file token.yaml stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
    TOKEN_PATH = 'token.yaml'.freeze
    SCOPE = Google::Apis::GmailV1::AUTH_GMAIL_READONLY

    def handle_two_step_or_factor(response)
      # extract `x-apple-id-session-id` and `scnt` from response, to be used by `update_request_headers`
      @x_apple_id_session_id = response["x-apple-id-session-id"]
      @scnt = response["scnt"]

      # get authentication options
      r = request(:get) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth")
        update_request_headers(req)
      end

      if r.body.kind_of?(Hash) && r.body["trustedDevices"].kind_of?(Array)
        handle_two_step(r)
      elsif r.body.kind_of?(Hash) && r.body["trustedPhoneNumbers"].kind_of?(Array) && r.body["trustedPhoneNumbers"].first.kind_of?(Hash)
        handle_two_factor(r)
      else
        raise "Although response from Apple indicated activated Two-step Verification or Two-factor Authentication, spaceship didn't know how to handle this response: #{r.body}"
      end
    end

    def handle_two_step(response)
      if response.body.fetch("securityCode", {})["tooManyCodesLock"].to_s.length > 0
        raise Tunes::Error.new, "Too many verification codes have been sent. Enter the last code you received, use one of your devices, or try again later."
      end

      puts("Two-step Verification (4 digits code) is enabled for account '#{self.user}'")
      puts("More information about Two-step Verification: https://support.apple.com/en-us/HT204152")
      puts("")

      puts("Please select a trusted device to verify your identity")
      available = response.body["trustedDevices"].collect do |current|
        "#{current['name']}\t#{current['modelName'] || 'SMS'}\t(#{current['id']})"
      end
      result = available[0]

      device_id = result.match(/.*\t.*\t\((.*)\)/)[1]
      handle_two_step_for_device(device_id)
    end

    # this is extracted into its own method so it can be called multiple times (see end)
    def handle_two_step_for_device(device_id)
      # Request token to device
      r = request(:put) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/device/#{device_id}/securitycode")
        update_request_headers(req)
      end

      # we use `Spaceship::TunesClient.new.handle_itc_response`
      # since this might be from the Dev Portal, but for 2 step
      Spaceship::TunesClient.new.handle_itc_response(r.body)

      puts("Successfully requested notification")
      code = get_code
      if code
        puts("Requesting session...")

        # Send token to server to get a valid session
        r = request(:post) do |req|
          req.url("https://idmsa.apple.com/appleauth/auth/verify/device/#{device_id}/securitycode")
          req.headers['Content-Type'] = 'application/json'
          req.body = { "code" => code.to_s }.to_json
          update_request_headers(req)
        end

        begin
          Spaceship::TunesClient.new.handle_itc_response(r.body) # this will fail if the code is invalid
        rescue => ex
          # If the code was entered wrong
          # {
          #   "securityCode": {
          #     "code": "1234"
          #   },
          #   "securityCodeLocked": false,
          #   "recoveryKeyLocked": false,
          #   "recoveryKeySupported": true,
          #   "manageTrustedDevicesLinkName": "appleid.apple.com",
          #   "suppressResend": false,
          #   "authType": "hsa",
          #   "accountLocked": false,
          #   "validationErrors": [{
          #     "code": "-21669",
          #     "title": "Incorrect Verification Code",
          #     "message": "Incorrect verification code."
          #   }]
          # }
          if ex.to_s.include?("verification code") # to have a nicer output
            puts("Error: Incorrect verification code")
            return handle_two_step_for_device(device_id)
          end

          raise ex
        end

        store_session

        return true
      else
        puts "Failed to get code."
        return false
      end
    end

    def handle_two_factor(response, depth = 0)
      if depth == 0
        puts("Two-factor Authentication (6 digits code) is enabled for account '#{self.user}'")
        puts("More information about Two-factor Authentication: https://support.apple.com/en-us/HT204915")
        puts("")

        two_factor_url = "https://github.com/fastlane/fastlane/tree/master/spaceship#2-step-verification"
        puts("If you're running this in a non-interactive session (e.g. server or CI)")
        puts("check out #{two_factor_url}")
      end

      # "verification code" has already be pushed to devices

      security_code = response.body["securityCode"]
      # "securityCode": {
      # 	"length": 6,
      # 	"tooManyCodesSent": false,
      # 	"tooManyCodesValidated": false,
      # 	"securityCodeLocked": false
      # },
      code_length = security_code["length"]

      puts("")
      env_2fa_sms_default_phone_number = 4844024191

      if env_2fa_sms_default_phone_number
        raise Tunes::Error.new, "Environment variable SPACESHIP_2FA_SMS_DEFAULT_PHONE_NUMBER is set, but empty." if env_2fa_sms_default_phone_number.empty?

        puts("Environment variable `SPACESHIP_2FA_SMS_DEFAULT_PHONE_NUMBER` is set, automatically requesting 2FA token via SMS to that number")
        puts("SPACESHIP_2FA_SMS_DEFAULT_PHONE_NUMBER = #{env_2fa_sms_default_phone_number}")
        puts("")
        phone_number = env_2fa_sms_default_phone_number
        phone_id = phone_id_from_number(response.body["trustedPhoneNumbers"], phone_number)
        code_type = 'phone'
        body = request_two_factor_code_from_phone(phone_id, phone_number, code_length)
      end

      puts("Requesting session...")

      # Send "verification code" back to server to get a valid session
      r = request(:post) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/#{code_type}/securitycode")
        req.headers['Content-Type'] = 'application/json'
        req.body = body
        update_request_headers(req)
      end

      begin
        # we use `Spaceship::TunesClient.new.handle_itc_response`
        # since this might be from the Dev Portal, but for 2 factor
        Spaceship::TunesClient.new.handle_itc_response(r.body) # this will fail if the code is invalid
      rescue => ex
        # If the code was entered wrong
        # {
        #   "service_errors": [{
        #     "code": "-21669",
        #     "title": "Incorrect Verification Code",
        #     "message": "Incorrect verification code."
        #   }],
        #   "hasError": true
        # }

        if ex.to_s.include?("verification code") # to have a nicer output
          puts("Error: Incorrect verification code")
          depth += 1
          return handle_two_factor(response, depth)
        end

        raise ex
      end

      store_session

      return true
    end

    # extracted into its own method for testing
    def ask_for_2fa_code(text)
      ask(text)
    end

    def phone_id_from_number(phone_numbers, phone_number)
      characters_to_remove_from_phone_numbers = ' \-()"'

      # start with e.g. +49 162 1234585 or +1-123-456-7866
      phone_number = phone_number.tr(characters_to_remove_from_phone_numbers, '')
      # cleaned: +491621234585 or +11234567866

      phone_numbers.each do |phone|
        # rubocop:disable Style/AsciiComments
        # start with: +49 •••• •••••85 or +1 (•••) •••-••66
        number_with_dialcode_masked = phone['numberWithDialCode'].tr(characters_to_remove_from_phone_numbers, '')
        # cleaned: +49•••••••••85 or +1••••••••66
        # rubocop:enable Style/AsciiComments

        maskings_count = number_with_dialcode_masked.count('•') # => 9 or 8
        pattern = /^([0-9+]{2,4})([•]{#{maskings_count}})([0-9]{2})$/
        # following regex: range from maskings_count-2 because sometimes the masked number has 1 or 2 dots more than the actual number
        # e.g. https://github.com/fastlane/fastlane/issues/14969
        replacement = "\\1([0-9]{#{maskings_count - 2},#{maskings_count}})\\3"
        number_with_dialcode_regex_part = number_with_dialcode_masked.gsub(pattern, replacement)
        # => +49([0-9]{8,9})85 or +1([0-9]{7,8})66

        backslash = '\\'
        number_with_dialcode_regex_part = backslash + number_with_dialcode_regex_part
        number_with_dialcode_regex = /^#{number_with_dialcode_regex_part}$/
        # => /^\+49([0-9]{8})85$/ or /^\+1([0-9]{7,8})66$/

        return phone['id'] if phone_number =~ number_with_dialcode_regex
        # +491621234585 matches /^\+49([0-9]{8})85$/
      end

      # Handle case of phone_number not existing in phone_numbers because ENV var is wrong or matcher is broken
      raise Tunes::Error.new, %(
Could not find a matching phone number to #{phone_number} in #{phone_numbers}.
Make sure your environment variable is set to the correct phone number.
If it is, please open an issue at https://github.com/fastlane/fastlane/issues/new and include this output so we can fix our matcher. Thanks.
)
    end

    def phone_id_from_masked_number(phone_numbers, masked_number)
      phone_numbers.each do |phone|
        return phone['id'] if phone['numberWithDialCode'] == masked_number
      end
    end

    def request_two_factor_code_from_phone_choose(phone_numbers, code_length)
      puts("Please select a trusted phone number to send code to:")

      available = phone_numbers.collect do |current|
        current['numberWithDialCode']
      end
      chosen = available[0]
      phone_id = phone_id_from_masked_number(phone_numbers, chosen)

      request_two_factor_code_from_phone(phone_id, chosen, code_length)
    end

    # this is used in two places: after choosing a phone number and when a phone number is set via ENV var
    def request_two_factor_code_from_phone(phone_id, phone_number, code_length)
      # Request code
      r = request(:put) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/phone")
        req.headers['Content-Type'] = 'application/json'
        req.body = { "phoneNumber" => { "id" => phone_id }, "mode" => "sms" }.to_json
        update_request_headers(req)
      end

      # we use `Spaceship::TunesClient.new.handle_itc_response`
      # since this might be from the Dev Portal, but for 2 step
      Spaceship::TunesClient.new.handle_itc_response(r.body)

      puts("Successfully requested text message to #{phone_number}")

      code = get_code

      return { "securityCode" => { "code" => code.to_s }, "phoneNumber" => { "id" => phone_id }, "mode" => "sms" }.to_json
    end

    def store_session
      # If the request was successful, r.body is actually nil
      # The previous request will fail if the user isn't on a team
      # on App Store Connect, but it still works, so we're good

      # Tell iTC that we are trustworthy (obviously)
      # This will update our local cookies to something new
      # They probably have a longer time to live than the other poor cookies
      # Changed Keys
      # - myacinfo
      # - DES5c148586dfd451e55afb0175f62418f91
      # We actually only care about the DES value

      request(:get) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/2sv/trust")
        update_request_headers(req)
      end
      # This request will fail if the user isn't added to a team on iTC
      # However we don't really care, this request will still return the
      # correct DES... cookie

      self.store_cookie
    end

    # Responsible for setting all required header attributes for the requests
    # to succeed
    def update_request_headers(req)
      req.headers["X-Apple-Id-Session-Id"] = @x_apple_id_session_id
      req.headers["X-Apple-Widget-Key"] = self.itc_service_key
      req.headers["Accept"] = "application/json"
      req.headers["scnt"] = @scnt
    end

    def authorize
      client_id = Google::Auth::ClientId.from_file(CREDENTIALS_PATH)
      token_store = Google::Auth::Stores::FileTokenStore.new(file: TOKEN_PATH)
      authorizer = Google::Auth::UserAuthorizer.new(client_id, SCOPE, token_store)
      user_id = 'default'
      credentials = authorizer.get_credentials(user_id)
      if credentials.nil?
        url = authorizer.get_authorization_url(base_url: OOB_URI)
        puts 'Open the following URL in the browser and enter the ' \
         "resulting code after authorization:\n" + url
        code = gets
        credentials = authorizer.get_and_store_credentials_from_code(
            user_id: user_id, code: code, base_url: OOB_URI
        )
      end
      credentials
    end

    def get_code
      # Initialize the API
      # API must be enabled for gmail acocunt - https://developers.google.com/classroom/quickstart/ruby
      # Add credentials.json to auto directory
      # First login - open link in console, get code and enter in console to autheniticat
      service = Google::Apis::GmailV1::GmailService.new
      service.client_options.application_name = APPLICATION_NAME
      service.authorization = authorize

      # Show the user's labels

      sleep(15)

      puts "Reading Email"
      user_id = 'me'
      result = service.list_user_labels(user_id)

      maxAttempts = 2
      i = 0
      isCode = false
      now = DateTime.now()
      now = (now.to_time - 40).to_datetime

      while (isCode == false && i < maxAttempts)
        puts "Waiting for code email"
        i += 1

        message = service.list_user_messages(user_id)
        id = message.messages[0].id

        result = service.get_user_message(user_id, id)
        payload = result.payload
        headers = payload.headers

        date = headers.any? { |h| h.name == 'Date' } ? headers.find { |h| h.name == 'Date' }.value : ''
        subject = headers.any? { |h| h.name == 'Subject' } ? headers.find { |h| h.name == 'Subject' }.value : ''
        body = payload.body
        emailDate = DateTime.rfc2822(date)

        if (now < emailDate && subject.include?("New text message from"))
          isCode = true
          jsonObj = JSON.parse(result.to_json)
          messageBody = jsonObj['snippet']
          str1_markerstring = "Code is: "
          str2_markerstring = " "
          code = messageBody[/#{str1_markerstring}(.*?)#{str2_markerstring}/m, 1]
          puts jsonObj['snippet']
          return code
        else
          now = DateTime.now()
          sleep(20)
        end
      end

      return false
    end

  end
end
