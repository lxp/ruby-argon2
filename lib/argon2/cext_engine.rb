require 'argon2/cext/argon2'

module Argon2
  # The engine class shields users from the C extension interface.
  # It is generally not advised to directly use this class.
  class Engine
    def self.hash_argon2i(password, salt, t_cost, m_cost)
      ret = CExt.argon2i_hash_raw(t_cost, 1 << m_cost, 1, password, salt)
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.instance_of?(String)
      ret.unpack('H*').join
    end

    def self.hash_argon2i_encode(password, salt, t_cost, m_cost, secret)
      if salt.length != Constants::SALT_LEN
        raise ArgonHashFail, "Invalid salt size"
      end
      ret = CExt.argon2_wrap(password, salt, t_cost, (1 << m_cost), 1, secret)
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.instance_of?(String)
      ret
    end

    def self.argon2i_verify(pwd, hash, secret)
      ret = CExt.wrap_argon2_verify(hash, pwd, secret)
      return false if ERRORS[ret.abs] == 'ARGON2_DECODING_FAIL'
      raise ArgonHashFail, ERRORS[ret.abs] unless ret == 0
      true
    end
  end
end
