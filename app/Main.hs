{-# LANGUAGE Arrows, NoMonomorphismRestriction #-}
module Main where

import Control.Monad
import Scanner.Scan
import System.Environment
import System.Exit
import System.Posix.User

concatCmd :: IO ()
concatCmd = combineFromDir >>= print

scanCmd :: [String] -> IO ()
scanCmd ips = makeScans ips allScans >>= print

cleanCmd :: IO ()
cleanCmd = cleanDir

main :: IO ()
main = do
    uid <- getEffectiveUserID
    unless (uid == 0) $ do
        putStrLn "You must run this as root"
        exitFailure

    args <- getArgs
    case args of
      "scan":[] -> do
          putStrLn "usage: nmap-exe scan [ips]"
          exitFailure
      "scan":ips -> scanCmd ips
      "cc":[] -> concatCmd
      "clean":[] -> cleanCmd
      "concat":[] -> concatCmd
      _ -> do
          putStrLn "usage: nmap-exe [scan,concat,clean]"
          exitFailure
