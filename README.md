# CTAMail

This is a rewrite of HectaMail, a now derelict python-based maddy frontend, using Golang.

## Nice, how do I host my own

Just git clone, go build, copy & edit the config and run the executable:
```
git clone https://concord.hectabit.org/HectaBit/CTAMail.git --depth=1
cd CTAMail
go build
cp config.ini.example config.ini
nano config.ini # Or vim or what have you
./ctamail
```

Read `ERRORS.md` for more infomation on server administration and errors.

## Great! What's the API?

You don't need the API. It's not designed to be interfaced with outside of itself, unlike other Burger-based software, and is entirely self contained. If you *must*, we do not provide offical support and you should just read `main.go`.