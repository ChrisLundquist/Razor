require "erb"
require "net/http"

# Root ProjectRazor namespace
module ProjectRazor
  module ModelTemplate
    # Root Model object
    # @abstract
    class NetbootBase
      class Base < ProjectRazor::ModelTemplate::Base
      include(ProjectRazor::Logging)

      # Compatible Image Prefix
      attr_accessor :image_prefix
      attr_accessor :password
      attr_accessor :kickstart_url # Where to find our kickstart file
      attr_accessor :netboot_url   # Where to find initrd.img and vmlinuz


      def initialize(hash)
        super(hash)
        # Static config
        @hidden                  = true
        #@template                = :netboot #TODO
        @name                    = "Netboot"
        @description             = "Netboot from a remote URL"
        # State / must have a starting state
        @current_state           = :init
        # Image prefix we can attach
        @image_prefix            = "net"
        # Enable agent brokers for this model
        @broker_plugin           = nil
        @final_state             = :os_complete
        # Metadata vars
        @root_password           = nil
        @hostname_prefix         = nil
        @kickstart_url           = nil
        @netboot_url             = nil
        @req_metadata_hash       = {
            "@root_password"           => { :default     => "test1234",
                                            :example     => "P@ssword!",
                                            :validation  => '^[\S]{8,}',
                                            :required    => true,
                                            :description => "root password (> 8 characters)" },
            "@hostname_prefix"         => { :default     => "",
                                            :example     => "net",
                                            :validation  => '^[A-Za-z\d-]{3,}$',
                                            :required    => true,
                                            :description => "Prefix for naming node" },
            "@kickstart_url"           => { :default     => "",
                                            :example     => "http://www.example.com/kickstart/example.ks",
                                            :validation  => '^[A-Za-z\d-]{3,}$', #TODO
                                            :required    => true,
                                            :description => "The url to find the kickstart file" },
            "@netboot_url"             => { :default     => "",
                                            :example     => "http://www.example.com/linux/distro/version/arch/os",
                                            :validation  => '^[A-Za-z\d-]{3,}$', #TODO
                                            :required    => true,
                                            :description => "The url to find the initrd.img and vmlinuz" },
        }

        from_hash(hash) if hash
      end

      def node_hostname
        @hostname_prefix + @counter.to_s
      end

      def broker_proxy_handoff
        logger.debug "Broker proxy called for: #{@broker.name}"
        unless node_ip_address
          logger.error "Node IP address isn't known"
          @current_state = :broker_fail
          broker_fsm_log
        end
        options = {
            :username                => "root",
            :password                => @root_password,
            :metadata                => node_metadata,
            :hostname                => node_hostname,
            :uuid                    => @node.uuid,
        #   :ipaddress               => node_ip_address, #TODO
        }
        @current_state = @broker.proxy_hand_off(options)
        broker_fsm_log
      end

      def callback
        { "boot_cfg"    => :boot_cfg,
          "kickstart"   => :kickstart,
          "postinstall" => :postinstall }
      end

      def fsm_tree
        {
            :init          => { :mk_call         => :init,
                                :boot_call       => :init,
                                :kickstart_start => :preinstall,
                                :kickstart_file  => :init,
                                :kickstart_end   => :postinstall,
                                :timeout         => :timeout_error,
                                :error           => :error_catch,
                                :else            => :init },
            :preinstall    => { :mk_call           => :preinstall,
                                :boot_call         => :preinstall,
                                :kickstart_start   => :preinstall,
                                :kickstart_file    => :init,
                                :kickstart_end     => :postinstall,
                                :kickstart_timeout => :timeout_error,
                                :error             => :error_catch,
                                :else              => :preinstall },
            :postinstall   => { :mk_call           => :postinstall,
                                :boot_call         => :postinstall,
                                :postinstall_end   => :os_complete,
                                :kickstart_file    => :postinstall,
                                :kickstart_end     => :postinstall,
                                :kickstart_timeout => :postinstall,
                                :error             => :error_catch,
                                :else              => :preinstall },
            :os_complete   => { :mk_call   => :os_complete,
                                :boot_call => :os_complete,
                                :else      => :os_complete,
                                :reset     => :init },
            :timeout_error => { :mk_call   => :timeout_error,
                                :boot_call => :timeout_error,
                                :else      => :timeout_error,
                                :reset     => :init },
            :error_catch   => { :mk_call   => :error_catch,
                                :boot_call => :error_catch,
                                :else      => :error_catch,
                                :reset     => :init },
        }
      end

      def mk_call(node, policy_uuid)
        super(node, policy_uuid)
        case @current_state
          # We need to reboot
          when :init, :preinstall, :postinstall, :os_complete
            ret = [:reboot, { }]
          when :timeout_error, :error_catch
            ret = [:acknowledge, { }]
          else
            ret = [:acknowledge, { }]
        end
        fsm_action(:mk_call, :mk_call)
        ret
      end

      def boot_call(node, policy_uuid)
        super(node, policy_uuid)
        case @current_state
          when :init, :preinstall
            ret = start_install(node, policy_uuid)
          when :postinstall, :os_complete, :broker_check, :broker_fail, :broker_success, :complete_no_broker
            ret = local_boot(node)
          when :timeout_error, :error_catch
            engine = ProjectRazor::Engine.instance
            ret    = engine.default_mk_boot(node.uuid)
          else
            engine = ProjectRazor::Engine.instance
            ret    = engine.default_mk_boot(node.uuid)
        end
        fsm_action(:boot_call, :boot_call)
        ret
      end

      def start_install(node, policy_uuid)
        ip = "#!ipxe\n"
        ip << "echo Reached #{@label} model boot_call\n"
#        ip << "echo Our image UUID is: #{@image_uuid}\n"
        ip << "echo Our state is: #{@current_state}\n"
        ip << "echo Our node UUID: #{node.uuid}\n"
        ip << "\n"
        ip << "echo We will be running an install now\n"
        ip << "sleep 3\n"
        ip << "\n"
#        ip << "kernel --name mboot.c32 #{image_svc_uri}/#{@image_uuid}/mboot.c32\n"
        ip << "imgargs mboot.c32 -c #{api_svc_uri}/policy/callback/#{policy_uuid}/boot_cfg\n"
        ip << "boot\n"
        ip
      end

      def local_boot(node)
        ip = "#!ipxe\n"
        ip << "echo Reached #{@label} model boot_call\n"
#        ip << "echo Our image UUID is: #{@image_uuid}\n"
        ip << "echo Our state is: #{@current_state}\n"
        ip << "echo Our node UUID: #{node.uuid}\n"
        ip << "\n"
        ip << "echo Continuing local boot\n"
        ip << "sleep 3\n"
        ip << "\n"
        ip << "sanboot --no-describe --drive 0x80\n"
        ip
      end

      def kickstart
        @arg = @args_array.shift
        case @arg
          when "start"
            fsm_action(:kickstart_start, :kickstart)
            return "ok"
          when "end"
            fsm_action(:kickstart_end, :kickstart)
            return "ok"
          when "file"
            fsm_action(:kickstart_file, :kickstart)
            return kickstart_file
          else
            return "error"
        end
      end

      def postinstall
        @arg = @args_array.shift
        case @arg
          when "end"
            fsm_action(:postinstall_end, :postinstall)
            return "ok"
          when "debug"
            # TODO
          else
            return "error"
        end
      end

      def boot_cfg
        config = "ks=#{kickstart_url}\n"
        config << "method=#{netbot_url}"
        config
      end

      def kickstart_file
        @kickstart_file ||= download_kickstart_file
      end

      def download_kickstart_file
         uri = URI kickstart_url
         Net::HTTP.get(uri)
      end
    end
  end
end
end
