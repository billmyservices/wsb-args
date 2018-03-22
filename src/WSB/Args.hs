{-# LANGUAGE OverloadedStrings #-}
{-|
Module      : WSB operations arguments
Description : Define all the required argument to operate with WSB service including HMAC encryption
Copyright   : (c) josejuan, 2017
License     : GPL-3
Maintainer  : jose-juan@computer-mind.com
Stability   : experimental
Portability : POSIX

Define all the required argument to operate with WSB service including HMAC encryption.
Is used by "wsb" and "wsb-client" for HMAC computation.
You should not use this module, use "wsb-client" instead.
-}
module WSB.Args (
  Args(..)
, mkArgs
, computeHMAC
, toBS
) where

import Crypto.Hash.Algorithms (SHA256)
import Crypto.MAC.HMAC
import Data.ByteString (ByteString)
import Data.ByteString.Base64 (encode)
import Data.ByteString.Conversion
import Data.Int (Int64)
import Data.Text (Text)
import WSB.CounterVersion
import qualified Crypto.MAC.HMAC as Crypto
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

-- |Contains all possible information for any WSB operation
data Args = Args { argUserId          :: Int64                -- ^The user id, you can find it at your profile page
                 , argCounterTypeCode :: Maybe Text           -- ^Your own counter type code, should be unique for each user
                 , argCounterCode     :: Maybe Text           -- ^Your own counter code, should be unique for each counter type
                 , argName            :: Maybe Text           -- ^For counter type creation this is the name
                 , argValue           :: Maybe Int64          -- ^The counter type default value or the operation value over some counter
                 , argK1              :: Maybe Int64          -- ^For counter type creation this is the first configuration value
                 , argK2              :: Maybe Int64          -- ^For counter type creation this is the second configuration value
                 , argMode            :: Maybe CounterVersion -- ^For counter type creation this is the counter behavior
                 , argTime            :: Maybe Int            -- ^The request time in Unix Epoch Time
                 , argHMAC            :: Maybe BS.ByteString  -- ^For each request it contains all the previous fields, encrypted with
                                                              --  your secret key and base64 encoded. You can find or create a new one
                                                              --  secret key at your profile page
                 } deriving (Eq, Show)

-- |Construct an empty `Args`
mkArgs :: Int64 -> Args
mkArgs userId = Args userId Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- |Strict version of `toByteString`
toBS :: ToByteString a => a -> ByteString
toBS = LBS.toStrict . toByteString

-- |For given Args, it compute the encrypted HMAC encoding result to
-- Base64. All `Args` fields are used but `argHMAC`.
computeHMAC :: Args -> ByteString -> ByteString
computeHMAC args@(Args a b c d e f g h i _) skey =
  let hdata = BS.concat $ [toBS a] ++ (m <$> [b,c,d]) ++ (m <$> [e,f,g]) ++ (m <$> [show <$> h]) ++ (m <$> [i])
      m :: ToByteString a => Maybe a -> ByteString
      m = maybe "" toBS
  in  encode $ BA.convert $ hmacGetDigest (Crypto.hmac skey hdata :: HMAC SHA256)

