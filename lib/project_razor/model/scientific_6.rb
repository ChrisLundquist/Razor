module ProjectRazor
  module ModelTemplate

    class Scientific6 < Redhat6
      include(ProjectRazor::Logging)

      def initialize(hash)
        super(hash)
        # Static config
        @hidden      = false
        @name        = "scientific_6"
        @description = "Scientific 6 Model"
        @osversion   = "6"

        from_hash(hash) unless hash == nil
        @req_metadata_hash = {
          "@hostname_prefix" => {
            :default     => "node",
            :example     => "node",
            :validation  => '^[\w]+$',
            :required    => true,
            :description => "node hostname prefix (will append node number)"
          },
          "@root_password" => {
            :default     => "test1234",
            :example     => "P@ssword!",
            :validation  => '^[\S]{8,}',
            :required    => true,
            :description => "root password (> 8 characters)"
          },
        }
      end

      def kernel_path
        "isolinux/vmlinuz0"
      end

      def initrd_path
        "isolinux/initrd0.img"
      end
    end
  end
end
