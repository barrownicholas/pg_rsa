DO $$
DECLARE
  private_key text := '-----BEGIN PRIVATE KEY-----
<your_test_key_here>
-----END PRIVATE KEY-----';
  result bytea;
BEGIN
  result := rsa_sign('hello.world', private_key, 'RS256');
  ASSERT result IS NOT NULL, 'RS256 signature should not be null';
  ASSERT length(result) > 0, 'RS256 signature should not be empty';
  RAISE NOTICE 'rsa_sign RS256: OK (% bytes)', length(result);

  result := rsa_sign('hello.world', private_key, 'RS384');
  ASSERT result IS NOT NULL, 'RS384 signature should not be null';
  ASSERT length(result) > 0, 'RS384 signature should not be empty';
  RAISE NOTICE 'rsa_sign RS384: OK (% bytes)', length(result);

  result := rsa_sign('hello.world', private_key, 'RS512');
  ASSERT result IS NOT NULL, 'RS512 signature should not be null';
  ASSERT length(result) > 0, 'RS512 signature should not be empty';
  RAISE NOTICE 'rsa_sign RS512: OK (% bytes)', length(result);

  result := rsa_sign('hello.world', private_key, 'RS999');
  ASSERT false, 'RS999 should have thrown an error';
EXCEPTION
  WHEN invalid_parameter_value THEN
    RAISE NOTICE 'rsa_sign RS999: correctly rejected unsupported algorithm';
END;
$$;
