# frozen_string_literal: true

# name: cc-track-forward
# about: Same-origin tracking endpoints that forward to local PHP endpoints (host nginx :8081)
# version: 0.2.0
# authors: you

after_initialize do
  require "base64"
  require "net/http"
  require "uri"
  require "time"

  module ::CcTrackForward
    # ==========================
    # HARD-CODED CONFIG (EDIT)
    # ==========================

    ENABLED = true

    # IMPORTANT:
    # - This is called from INSIDE the Discourse container.
    # - 127.0.0.1 here means the container, NOT the host.
    # - Common host gateway is 172.17.0.1 (default docker bridge), but verify on your server.
    CLICK_FORWARD_URL = "http://172.17.0.1:8081/discourse-click_simple.php"

    # Optional: protect the public endpoint from spam.
    # If blank, no protection. If set, JS calls /cc/click?k=SECRET
    INGRESS_SECRET_PARAM = "" # e.g. "ingresssecret123"

    # Optional: include a secret header to the host endpoint
    # (PHP/nginx can check X-Promo-Postback-Secret if you want)
    FORWARD_SECRET_HEADER = "" # e.g. "forwardsecret456"

    # Keep requests fast / non-blocking
    OPEN_TIMEOUT = 1.5
    READ_TIMEOUT = 1.5

    # 1x1 gif (same style as digest-open-tracker)
    GIF_1X1 = Base64.decode64("R0lGODlhAQABAPAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==").freeze
  end

  class ::CcTrackForward::Engine < ::Rails::Engine
    engine_name "cc_track_forward"
    isolate_namespace CcTrackForward
  end

  # ---------------------------
  # Background forwarder job
  # ---------------------------
  module ::Jobs
    class CcForwardClick < ::Jobs::Base
      def execute(args)
        return unless ::CcTrackForward::ENABLED

        forward_url = ::CcTrackForward::CLICK_FORWARD_URL.to_s.strip
        return if forward_url.empty?

        # Sidekiq args can arrive with string OR symbol keys
        p_hash  = args[:params]  || args["params"]  || {}
        ua      = args[:ua]      || args["ua"]      || ""
        xff     = args[:xff]     || args["xff"]     || ""
        real_ip = args[:real_ip] || args["real_ip"] || ""

        begin
          uri = URI.parse(forward_url)

          qs = URI.encode_www_form(p_hash || {})
          unless qs.empty?
            uri.query = [uri.query, qs].compact.reject(&:empty?).join("&")
          end

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == "https")
          http.open_timeout = ::CcTrackForward::OPEN_TIMEOUT
          http.read_timeout = ::CcTrackForward::READ_TIMEOUT

          req = Net::HTTP::Get.new(uri.request_uri)

          # Preserve browser UA (PHP can read either normal UA or X-Forwarded-User-Agent)
          if ua.to_s.length > 0
            req["User-Agent"] = ua.to_s
            req["X-Forwarded-User-Agent"] = ua.to_s
          end

          # Preserve client IP chain
          if xff.to_s.length > 0
            req["X-Forwarded-For"] = xff.to_s
            req["X-Real-IP"] = real_ip.to_s if real_ip.to_s.length > 0
          end

          # Optional secret header to the host endpoint
          secret = ::CcTrackForward::FORWARD_SECRET_HEADER.to_s.strip
          req["X-Promo-Postback-Secret"] = secret if secret.length > 0

          http.request(req)
        rescue => e
          Rails.logger.warn("[cc-track-forward] forward click failed: #{e.class}: #{e.message}")
        end
      end
    end
  end

  # ---------------------------
  # Controller (beacon style)
  # ---------------------------
  class ::CcTrackForward::TrackController < ::ActionController::Base
    protect_from_forgery with: :null_session

    def click_options
      render_pixel
    end

    def click
      return render_pixel unless ::CcTrackForward::ENABLED

      # Optional spam protection
      secret = ::CcTrackForward::INGRESS_SECRET_PARAM.to_s
      if secret.length > 0
        provided = params[:k].to_s
        return render_pixel unless provided == secret
      end

      # Basic validation similar to PHP
      type = params[:type].to_s
      sid  = params[:sid].to_s

      return render_pixel unless type == "topic_link_click"
      return render_pixel if sid.empty? || sid.length > 128

      link_url  = params[:link_url].to_s
      link_kind = params[:link_kind].to_s

      return render_pixel if link_url.empty?
      return render_pixel unless (link_kind == "internal" || link_kind == "external")

      # Forward only what PHP expects
      fwd_params = {
        "type"        => type,
        "sid"         => sid,
        "page_url"    => params[:page_url].to_s,
        "page_path"   => params[:page_path].to_s,
        "link_url"    => link_url,
        "link_kind"   => link_kind,
        "link_origin" => params[:link_origin].to_s,
        "new_tab"     => params[:new_tab].to_s,
        "dayofweek"   => params[:dayofweek].to_s
      }

      # UA + best-guess client IP
      ua = request.user_agent.to_s
      ip = request.remote_ip.to_s

      # Preserve any prior XFF chain (if you have a proxy in front already)
      prior_xff = request.get_header("HTTP_X_FORWARDED_FOR").to_s
      xff = prior_xff.empty? ? ip : "#{prior_xff}, #{ip}"

      # Enqueue so browser response is instant
      begin
        Jobs.enqueue(:cc_forward_click, params: fwd_params, ua: ua, xff: xff, real_ip: ip)
      rescue => e
        Rails.logger.warn("[cc-track-forward] enqueue failed: #{e.class}: #{e.message}")
      end

      render_pixel
    rescue => e
      Rails.logger.warn("[cc-track-forward] controller error: #{e.class}: #{e.message}")
      render_pixel
    end

    private

    def render_pixel
      gif = ::CcTrackForward::GIF_1X1

      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "0"
      response.headers["X-Content-Type-Options"] = "nosniff"
      response.headers["Access-Control-Allow-Origin"] = "*"
      response.headers["Content-Length"] = gif.bytesize.to_s

      response.status = 200
      response.content_type = "image/gif"
      self.response_body = gif
    end
  end

  # ---------------------------
  # Routes
  # ---------------------------
  CcTrackForward::Engine.routes.draw do
    get     "/click" => "track#click"
    options "/click" => "track#click_options"
  end

  Discourse::Application.routes.append do
    mount ::CcTrackForward::Engine, at: "/cc"
  end
end
