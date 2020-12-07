{-# LANGUAGE Arrows, NoMonomorphismRestriction #-}
module Main where

import Scanner.Nmap

main :: IO ()
-- main = makeScan "/tmp/res.xml" ["-p1-443"] ["10.10.10.17", "10.10.10.43"] >>= print
main = parse "/tmp/res6.xml" >>= print
