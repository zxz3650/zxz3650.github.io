---
layout: page
title: Intelligence Archive
---

<p class="page-intro">Published research, incident-response notes, and technical intelligence in reverse chronological order.</p>

<div class="archive-list">
  {% assign current_year = '' %}
  {% for post in site.posts %}
    {% assign post_year = post.date | date: '%Y' %}
    {% if post_year != current_year %}
      {% unless forloop.first %}</div>{% endunless %}
      <div class="archive-year"><h2>{{ post_year }}</h2>
      {% assign current_year = post_year %}
    {% endif %}
      <article>
        <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%m.%d" }}</time>
        <div><h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
        {% if post.tags %}<p>{{ post.tags | join: ' · ' }}</p>{% endif %}</div>
        <a href="{{ post.url | relative_url }}" aria-label="Read {{ post.title }}">↗</a>
      </article>
    {% if forloop.last %}</div>{% endif %}
  {% endfor %}
</div>
