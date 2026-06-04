# Diver OSINT CTF '25 - mgb-cti for Challenge ``P2T``

### In this Japanese based CTF, my team (SE4L) placed 15th out of 668 teams. The challenge below is just one of a few that I solved for my team with ``P2T`` being one of the harder ones to solve for non-Japanese speaking teams (like us). Below showcases my steps and findings along the way. Enjoy.


## ``P2T``
### Challenge Description:
``The photo posted to the left of this photo shows an animal. Answer its name as it is written in Japanese.-- Flag Format: Diver25{シバイヌ}``

### Challenge Image:
![P2T Challenge Image](https://github.com/user-attachments/assets/50a7b76f-644b-4af1-a590-1558ea57e521)

### Steps to Flag:

Instantly I noticed a few things that stuck out about this image (see below) - 
  1. The gold 'x' that can be seen in the laminated paper stood out as either a unique light design or some type of display.
  2. The white 'c' shape which I believed to be another light source, like something circular or a window.
  3. The Japanese text on the right - this stood to be a problem in particular for non-Japanese speaking teams since each translation websites interpreted this text differently, but all had a similar theme of 'mountains, goats, lions, peace, roar, silence'.
  4. Finally, the laminated sheet itself looked amateur at best. My first thought with this was that it was either a school project or some community display at like a park or some location similar.
![Image](https://github.com/user-attachments/assets/41275489-5476-4f9b-a687-0cf26f7268ab)


Moving on with these new ideas in my head, I kept trying to find a more solidified translation and this was when my teammates shared that they found one that provided the answer ``Mt. Tateyama`` from the text ``立山`` in the image. -- This find was very important as without it,
we would have been stuck without a next step. This also confirmed my idea that this would be located a park of some sorts, so I jumped to Google Maps and searched for any campsite building or a community center.

I ended up locating the ``Mount Tateyama Visitor Center`` which ended up confirming a lot of details.
![Image](https://github.com/user-attachments/assets/e1cda9fe-7cac-4de7-8d03-6c0cf8a00c3a)

I quickly jumped into some of the photospheres that were inside of the building, in hopes to find some confirming facts, which ended up being the case. (see images below) -- This image was a big confirmation that I was heading in the right direction since the highlighted areas matched the challenge image.

![Image](https://github.com/user-attachments/assets/06304051-76ca-4849-b7ee-91c33da2d890)

More confirmation below -- As you can see my idea about a window and the gold 'X' light decor was correct. 

![Image](https://github.com/user-attachments/assets/f343e2ca-bca8-471a-9ab4-07a8150e3bb7)

After a little more looking, I found another photo with our little birdie friend! Now, all I had to do was find a more high quality photo of that same wall so I could get the name for the flag.

![Image](https://github.com/user-attachments/assets/84704656-5e71-470f-a6f3-45e05cdd90a5)

With a little more digging, I quickly found this great high quality image that matches the bird that is needed for the flag.

![Image](https://github.com/user-attachments/assets/d876256b-8a31-4a78-89d6-4db993437923)

``トビ``

### This ended up being the correct flag ``Diver25{トビ}``





