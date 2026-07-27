# Diver OSINT CTF 2026 - Writeup for Challenge ``trot``
-------
## ``trot``
### Challenge Description:
```Website: https://www.reddit.com/r/Awww/comments/1kej10n/is_that_a_mini_schnauzer/```

```かわいい小犬が彫刻の前を駆け抜けていった。この彫刻の作者をラテン文字表記で答えよ。```
```例えば、Leonardo da Vinciが作者の場合、Flagは Diver26{Leonardo da Vinci} となる。```

```A cute puppy trotted past the sculpture. Answer the name of the sculpture's creator in Latin characters. For example, if the creator is Leonardo da Vinci, the flag should be Diver26{Leonardo da Vinci}.```

### Challenge Video URL: 
https://www.reddit.com/r/Awww/comments/1kej10n/is_that_a_mini_schnauzer/


### Steps to Flag:

<img width="483" height="651" alt="image" src="https://github.com/user-attachments/assets/af8566db-167b-4414-abc4-f83d7c56af7d" />

### First I took note of a few things from one of the first frames in the video:
  - Pharmacy/Medical '+' sign
  - Shop below the '+' pharmacy sign that looks like it begins with "Deu-------------"
  - Rectangular, gray slate pavers making up the road


----

<img width="484" height="610" alt="image" src="https://github.com/user-attachments/assets/a73b4d8d-1225-4bc6-9c5f-b90a647cede9" />


### In a further frame, I noticed another key piece of info
  - The white, large planter tree boxes that line the edge of the street.

----
<img width="945" height="554" alt="image" src="https://github.com/user-attachments/assets/b660b087-43f6-4e06-8309-7d4b3d380a74" />

### Assuming that this was potentially France (from the green medical sign), I did a Google Reverse Image search with the query `France`. 

-----

<img width="943" height="727" alt="image" src="https://github.com/user-attachments/assets/b0dbc128-2ac5-499e-924e-c08d196fd1ca" />

### This yielded a similar looking area from a CNN article as seen above. If you noticed, the CNN article also features the large, white tree planter boxes.

### The result from the CNN article reports that this event happened in Nice, France - which helps narrow down our search to a specific city.

<img width="1455" height="918" alt="image" src="https://github.com/user-attachments/assets/121aa4be-5080-49e3-9b80-8eb9d4586dbd" />

-----

### Now that I knew we were located in Nice, I began brute force searching through every pharmacy in Nice. Specifically looking for the **unique font that "PH(armacy)"** was written in.

<img width="958" height="473" alt="image" src="https://github.com/user-attachments/assets/4d154031-51d9-4712-85fe-8d78a8cb4d87" />

-----
### You can see quite quickly that just from the first image on a Google Map tag that none of these match our desired store front, font, or style of archiecture.

<img width="596" height="669" alt="image" src="https://github.com/user-attachments/assets/57878624-0120-415a-b9a6-bc22b11d832c" />
<img width="819" height="671" alt="image" src="https://github.com/user-attachments/assets/df6aaae1-a61a-407e-b1b5-7384ca7ec451" />

-----

### After a brief moment of searching, I came across this image which does match our desired archiecture, font style, and medical cross ('+') while still located in Nice, France.

<img width="958" height="506" alt="image" src="https://github.com/user-attachments/assets/16a6d4ee-3de5-4f08-9ed4-c3379c5149f3" />

-----

### Upon clicking into the Google Street View in the newly found pharmacy's vicinity, you will quickly see how well this location matches up to the provided Reddit video of the 'trot'.

<img width="958" height="487" alt="image" src="https://github.com/user-attachments/assets/9c533dfd-0478-4047-ad7f-ef85951ae47b" />

----

### Now, we have that we have found the location of the 'trot' video, we are still not done with the challenge! **We must locate the statue and it's creator**.

<img width="1042" height="670" alt="image" src="https://github.com/user-attachments/assets/a72a805f-ce92-4ad6-b4a5-cbe519cef5ee" />

---

### With a quick Google search, we have the flag:

### The correct flag: ``Diver26{Laurent Bosio}``

<img width="485" height="732" alt="image" src="https://github.com/user-attachments/assets/536442d1-b3a4-49e1-85a4-db322e99268f" />
