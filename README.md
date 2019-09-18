# sully

## Backward compatibility
The APIs are not stable, **do not use it in production**

## Introduction
Today Go community is at a disadvantageous position and the reason for this is: There is no library like [Warrant](https://github.com/capless/warrant) for Python that would help the Go community to work with the AWS Cognito constructs in a simplified way.

This package `sully` is an attempt to simplify the life of a Go developer when interacting with AWS Cognito.

Many thanks to [AlexRudd](https://github.com/AlexRudd). See the Credits section for details

## Why the name `Sully`
I chose this name after watching the movie [Sully](https://www.imdb.com/title/tt3263904/) in which [Tom Hanks](https://en.wikipedia.org/wiki/Tom_Hanks) plays the real life character of [Chesley Sullenberger](https://en.wikipedia.org/wiki/Chesley_Sullenberger) who is a speaker on airline safety, I saw it fit to name this library after Sully as this eases the developer's effort when working with AWS Cognito

## Credits
I have copied the SRP implementation for Cognito by @AlexRudd [cognito-srp](https://github.com/AlexRudd/cognito-srp/) to build a new library which does more than just SRP calculation
