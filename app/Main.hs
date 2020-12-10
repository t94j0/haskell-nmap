{-# LANGUAGE Arrows, NoMonomorphismRestriction #-}
module Main where

import Scanner.Scan

main :: IO ()
main = makeScans ["10.10.10.37"] [normalScan, agressiveScan] >>= print
-- main = parse "/tmp/res6.xml" >>= print
