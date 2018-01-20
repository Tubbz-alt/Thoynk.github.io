---
layout: post
title:  "Thoynk Is Collaborative Python ... and other things!"
date:   2018-01-19 12:41:30 -0600
categories: Thoynk update
---
This is a trial run of Jekyll for Thoynk ... we're trying Jekyll for a lot of different reasons, maybe because Jekyll offers powerful support for code snippets such as the Towers of Hanoi code from [Python Course](https://www.python-course.eu/python3_course.php):

{% highlight python %}
#=> just an example to show highlighting functionality ...
def hanoi(n, source, helper, target):
    if n > 0:
        # move tower of size n - 1 to helper:
        hanoi(n - 1, source, target, helper)
        # move disk from source peg to target peg
        if source:
            target.append(source.pop())
        # move tower of size n-1 from helper to target
        hanoi(n - 1, helper, source, target)

source = [4,3,2,1]
target = []
helper = []
hanoi(len(source),source,helper,target)

print source, helper, target
#=> just an example to show highlighting functionality ...
{% endhighlight %}

We could do something extremely clever with code ... like add something like [Datacamp Light][datacamp-light] to Jekyll ... and that might be a good exercise, but it would involve getting familiar with [Datacamp Light][datacamp-light] and read the [Jekyll docs][jekyll-docs] a time or two and of course getting familiar with the [Jekyll’s GitHub repo][jekyll-gh] ... and of course, there's the whole markdown-with-txt-code-snippets TO html-with-javascript-and-SASS ... to be able to maybe ask some somewhat more intelligent questions at [Jekyll Talk][jekyll-talk] or on the issue board at the [Datacamp Light repository][datacamp-light]. So, yes, doing something clever ultimately involves a learning skills to develop an deeper understanding of how things work AND, more importantly, how polyglot development communities work.

Of course, the cleverness really begs a much larger question ... WHY would we do it this way?  The answer is that it's not exactly just mere cleverness -- there's a benefit from talking about and giving the reader a chance to immediately play with the code snippets to illustrate the point we are attempting to convey. The point of all of it is a more collaborative learning experience ... ephemerally providing the reader with a more immediate, lower friction way to experiment with their own code snippet hopefully provides a more collaborative learning experience.  But is there a better way?  Why would we do it in THIS way, with THIS architecture? What can we improve in this teaching/writing method?

[jekyll-docs]:    https://jekyllrb.com/docs/home
[jekyll-gh]:      https://github.com/jekyll/jekyll
[jekyll-talk]:    https://talk.jekyllrb.com/
[datacamp-light]: https://github.com/datacamp/datacamp-light
